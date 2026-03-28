"""
Weekly incremental update pipeline.

Orchestrates:
1. Collection of new CVEs only → staging/
2. Identification of affected language partitions
3. Re-optimization of affected partitions only
4. Append of new metadata rows to metadata Parquets
5. Blob store handles dedup automatically
6. Rebuild DuckDB catalog + ANALYZE
7. Clear staging

Entry point:  run_weekly_update(config)
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

import polars as pl

from collection.nvd_importer import import_cves
from collection.cwe_importer import import_cwes
from collection.repo_collector import collect_repo_metadata, find_unavailable_urls
from collection.commit_extractor import run_collection
from storage.blob_store import BlobStore
from storage.catalog import build_catalog
from storage import writer as parquet_writer
from update import staging as stg

logger = logging.getLogger("cvefixes.merger")


def _existing_cve_ids(parquet_base: Path) -> set[str]:
    """Return CVE IDs already present in the production metadata."""
    cve_file = parquet_base / "metadata" / "cve.parquet"
    if not cve_file.exists():
        return set()
    return set(pl.read_parquet(cve_file)["cve_id"].to_list())


def _append_metadata(
    new_df: pl.DataFrame,
    parquet_file: Path,
    dedup_cols: list[str],
) -> None:
    """Append *new_df* rows to an existing metadata Parquet, deduplicating on *dedup_cols*."""
    if not parquet_file.exists():
        new_df.write_parquet(parquet_file, compression="zstd", compression_level=3)
        return
    existing = pl.read_parquet(parquet_file)
    combined = pl.concat([existing, new_df]).unique(subset=dedup_cols)
    combined.write_parquet(parquet_file, compression="zstd", compression_level=3)
    logger.info("Updated %s: %d rows total", parquet_file.name, len(combined))


def run_weekly_update(
    data_path: str | Path = "Data",
    parquet_base: str | Path = "parquet",
    duckdb_path: str | Path = "cvefixes.duckdb",
    github_user: str | None = None,
    github_token: str | None = None,
    sample_limit: int = 0,
    num_workers: int = 4,
) -> None:
    """
    Run the full weekly incremental update.

    Only processes CVEs that are new since the last run.
    Only rewrites affected language partitions.
    """
    t0 = time.perf_counter()
    data_path = Path(data_path)
    parquet_base = Path(parquet_base)
    blob_root = parquet_base / "blobs"

    blob_store = BlobStore(blob_root)
    staging_base = parquet_base

    logger.info("=== CVEfixes weekly update started ===")

    # ------------------------------------------------------------------
    # Step 1: Download new CVEs
    # ------------------------------------------------------------------
    logger.info("Step 1: Importing CVEs from NVD …")
    df_cve, df_fixes = import_cves(
        data_path=data_path,
        staging_path=parquet_base / "staging",
        sample_limit=sample_limit,
    )
    if df_cve is None or len(df_cve) == 0:
        logger.warning("No CVEs downloaded — aborting update")
        return

    # Filter to only new CVEs
    known_ids = _existing_cve_ids(parquet_base)
    df_cve_new = df_cve.filter(~pl.col("cve_id").is_in(known_ids))
    if len(df_cve_new) == 0:
        logger.info("No new CVEs found — nothing to do")
        return
    logger.info("Found %d new CVEs", len(df_cve_new))

    # Filter fixes to new CVEs only
    df_fixes_new = df_fixes.filter(pl.col("cve_id").is_in(df_cve_new["cve_id"].to_list()))

    # ------------------------------------------------------------------
    # Step 2: CWE classification for new CVEs
    # ------------------------------------------------------------------
    logger.info("Step 2: Importing CWEs …")
    df_cwe, df_class = import_cwes(
        data_path=data_path,
        staging_path=parquet_base / "staging",
        df_cve=df_cve_new,
    )

    # ------------------------------------------------------------------
    # Step 3: Validate repo availability
    # ------------------------------------------------------------------
    logger.info("Step 3: Validating repo URLs …")
    unique_urls = df_fixes_new["repo_url"].unique().to_list()
    unavailable = find_unavailable_urls(unique_urls)
    if unavailable:
        logger.info("Filtering %d unavailable repos", len(unavailable))
        df_fixes_new = df_fixes_new.filter(~pl.col("repo_url").is_in(unavailable))

    # ------------------------------------------------------------------
    # Step 4: Collect commits for new CVEs
    # ------------------------------------------------------------------
    logger.info("Step 4: Collecting commits …")
    done_hashes = stg.get_done_hashes(staging_base)
    run_collection(
        df_fixes=df_fixes_new,
        blob_store=blob_store,
        staging_path=parquet_base / "staging",
        num_workers=num_workers,
        already_done_hashes=done_hashes,
    )

    # ------------------------------------------------------------------
    # Step 5: Collect repository metadata
    # ------------------------------------------------------------------
    logger.info("Step 5: Collecting repository metadata …")
    collect_repo_metadata(
        df_fixes=df_fixes_new,
        staging_path=parquet_base / "staging",
        github_user=github_user,
        github_token=github_token,
    )

    # Persist fixes to staging for the writer
    fixes_stage = parquet_base / "staging" / "fixes_staging.parquet"
    df_fixes_new.write_parquet(fixes_stage, compression="zstd")

    # ------------------------------------------------------------------
    # Step 6: Identify affected language partitions
    # ------------------------------------------------------------------
    affected_langs = stg.get_affected_languages(staging_base)
    logger.info("Affected language partitions: %s", affected_langs or ["(none)"])

    # ------------------------------------------------------------------
    # Step 7: Append new metadata to production files, then rewrite only the
    # affected language partitions.  Using skip_metadata=True prevents
    # finalize() from overwriting existing production metadata with only the
    # new (staging) rows — _append_metadata() merges new + existing instead.
    # ------------------------------------------------------------------
    logger.info("Step 7: Appending new metadata rows to production files …")
    metadata_dir = parquet_base / "metadata"
    metadata_dir.mkdir(parents=True, exist_ok=True)

    # Load staging frames (may be None on a dry run)
    _stg_cve = stg.load(staging_base, "cve")
    _stg_fixes = stg.load(staging_base, "fixes")
    _stg_cwe = stg.load(staging_base, "cwe")
    _stg_class = stg.load(staging_base, "cwe_classification")
    _stg_repo = stg.load(staging_base, "repository")
    _stg_commits = stg.load(staging_base, "commits")

    if _stg_cve is not None:
        _append_metadata(_stg_cve, metadata_dir / "cve.parquet", ["cve_id"])
    if _stg_fixes is not None:
        _append_metadata(_stg_fixes, metadata_dir / "fixes.parquet", ["cve_id", "hash"])
    if _stg_cwe is not None:
        _append_metadata(_stg_cwe, metadata_dir / "cwe.parquet", ["cwe_id"])
    if _stg_class is not None:
        _append_metadata(_stg_class, metadata_dir / "cwe_classification.parquet", ["cve_id", "cwe_id"])
    if _stg_repo is not None:
        _append_metadata(_stg_repo, metadata_dir / "repository.parquet", ["repo_url"])
    if _stg_commits is not None:
        _append_metadata(_stg_commits, metadata_dir / "commits.parquet", ["hash"])

    logger.info("Step 7b: Rewriting affected language partitions …")
    parquet_writer.finalize(
        base_path=parquet_base,
        affected_languages=affected_langs if affected_langs else None,
        clear_staging=True,
        skip_metadata=True,
    )

    # ------------------------------------------------------------------
    # Step 8: Rebuild DuckDB catalog
    # ------------------------------------------------------------------
    logger.info("Step 8: Rebuilding DuckDB catalog …")
    con = build_catalog(parquet_base, duckdb_path)
    con.close()

    elapsed = time.perf_counter() - t0
    logger.info(
        "=== Update complete in %.1f s (%.0f min) ===",
        elapsed, elapsed / 60,
    )


def run_full_collection(
    data_path: str | Path = "Data",
    parquet_base: str | Path = "parquet",
    duckdb_path: str | Path = "cvefixes.duckdb",
    github_user: str | None = None,
    github_token: str | None = None,
    sample_limit: int = 0,
    num_workers: int = 4,
) -> None:
    """
    Run a complete (from-scratch) collection.  Equivalent to the original
    create_CVEfixes_from_scratch.sh but targeting Parquet/DuckDB.
    """
    t0 = time.perf_counter()
    data_path = Path(data_path)
    parquet_base = Path(parquet_base)
    blob_root = parquet_base / "blobs"
    blob_store = BlobStore(blob_root)

    logger.info("=== CVEfixes full collection started ===")

    # Step 1: CVEs
    logger.info("Step 1: Importing CVEs …")
    df_cve, df_fixes = import_cves(
        data_path=data_path,
        staging_path=parquet_base / "staging",
        sample_limit=sample_limit,
    )

    # Step 2: CWEs
    logger.info("Step 2: Importing CWEs …")
    import_cwes(
        data_path=data_path,
        staging_path=parquet_base / "staging",
        df_cve=df_cve,
    )

    # Step 3: Validate repos
    logger.info("Step 3: Validating repo availability …")
    unique_urls = df_fixes["repo_url"].unique().to_list()
    unavailable = find_unavailable_urls(unique_urls)
    if unavailable:
        df_fixes = df_fixes.filter(~pl.col("repo_url").is_in(unavailable))

    # Step 4: Commits
    logger.info("Step 4: Collecting commits …")
    run_collection(
        df_fixes=df_fixes,
        blob_store=blob_store,
        staging_path=parquet_base / "staging",
        num_workers=num_workers,
    )

    # Step 5: Repo metadata
    logger.info("Step 5: Collecting repository metadata …")
    collect_repo_metadata(
        df_fixes=df_fixes,
        staging_path=parquet_base / "staging",
        github_user=github_user,
        github_token=github_token,
    )

    # Persist fixes staging
    fixes_stage = parquet_base / "staging" / "fixes_staging.parquet"
    df_fixes.write_parquet(fixes_stage, compression="zstd")

    # Step 6: Optimization pass
    logger.info("Step 6: Finalizing Parquet layout …")
    parquet_writer.finalize(base_path=parquet_base, clear_staging=True)

    # Step 7: DuckDB catalog
    logger.info("Step 7: Building DuckDB catalog …")
    con = build_catalog(parquet_base, duckdb_path)
    con.close()

    elapsed = time.perf_counter() - t0
    logger.info(
        "=== Full collection complete in %.1f s (%.0f min) ===",
        elapsed, elapsed / 60,
    )
