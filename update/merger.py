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



import json
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

# ---------------------------------------------------------------------------
# Checkpoint / resumption helpers
# ---------------------------------------------------------------------------

class _CollectionState:
    """
    Lightweight persistent checkpoint store backed by a JSON file.

    Written after each pipeline step so that a re-run after a failure
    skips already-completed steps instead of starting from scratch.

    Location: ``{parquet_base}/collection_state.json``
    Deleted automatically on successful completion of all steps.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._data: dict = {}
        if path.exists():
            try:
                self._data = json.loads(path.read_text())
                logger.info("Resuming from checkpoint %s", path)
            except Exception:
                logger.warning("Checkpoint file corrupt — starting fresh")
                self._data = {}

    def is_done(self, step: str) -> bool:
        return bool(self._data.get("steps", {}).get(step))

    def mark_done(self, step: str, **extra) -> None:
        """Mark *step* as complete and persist any *extra* key/value pairs."""
        self._data.setdefault("steps", {})[step] = True
        self._data.update(extra)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(self._data, indent=2))
        logger.debug("Checkpoint: step '%s' done", step)

    def get(self, key: str, default=None):
        return self._data.get(key, default)

    def clear(self) -> None:
        if self._path.exists():
            self._path.unlink()
            logger.debug("Checkpoint file removed (collection complete)")


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
    nvd_api_key: str | None = None,
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

    blob_store = BlobStore(root=blob_root)
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
        nvd_api_key=nvd_api_key,
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
    nvd_api_key: str | None = None,
    sample_limit: int = 0,
    num_workers: int = 4,
) -> None:
    """
    Run a complete (from-scratch) collection targeting Parquet/DuckDB.

    **Resumable**: a ``collection_state.json`` checkpoint file is written
    after each major step.  If the process is interrupted and re-run, it
    skips already-completed steps automatically.  Delete the checkpoint
    file (or run with ``--reset``) to force a full restart.

    Steps:
      1. Download & import NVD CVE/fix records
      2. Download & import MITRE CWE records
      3. Validate repository URLs (HEAD requests)
      4. Traverse git commits and extract code changes → blob store + staging
      5. Fetch repository metadata from GitHub API
      6. Promote staging Parquets to sorted, partitioned production layout
      7. Build DuckDB catalog views
    """
    t0 = time.perf_counter()
    data_path = Path(data_path)
    parquet_base = Path(parquet_base)
    blob_root = parquet_base / "blobs"
    blob_store = BlobStore(root=blob_root)
    staging_path = parquet_base / "staging"

    state = _CollectionState(parquet_base / "collection_state.json")

    logger.info("=== CVEfixes full collection started ===")

    # ------------------------------------------------------------------
    # Step 1: CVE / fix import
    # ------------------------------------------------------------------
    if state.is_done("cve_import"):
        logger.info("Step 1: CVE import already done — loading staging")
        _cve = stg.load(parquet_base, "cve")
        _fix = stg.load(parquet_base, "fixes")
        df_cve  = _cve  if _cve  is not None else pl.DataFrame()
        df_fixes = _fix if _fix is not None else pl.DataFrame()
    else:
        logger.info("Step 1: Importing CVEs …")
        df_cve, df_fixes = import_cves(
            data_path=data_path,
            staging_path=staging_path,
            sample_limit=sample_limit,
            nvd_api_key=nvd_api_key,
        )
        state.mark_done("cve_import")

    # ------------------------------------------------------------------
    # Step 2: CWE import
    # ------------------------------------------------------------------
    if state.is_done("cwe_import"):
        logger.info("Step 2: CWE import already done — skipping")
    else:
        logger.info("Step 2: Importing CWEs …")
        import_cwes(
            data_path=data_path,
            staging_path=staging_path,
            df_cve=df_cve,
        )
        state.mark_done("cwe_import")

    # ------------------------------------------------------------------
    # Step 3: Validate repo URLs
    # ------------------------------------------------------------------
    if state.is_done("url_validation"):
        logger.info("Step 3: URL validation already done — skipping")
        unavailable = set(state.get("unavailable_urls", []))
    else:
        logger.info("Step 3: Validating repo URLs …")
        unique_urls = df_fixes["repo_url"].unique().to_list() if len(df_fixes) else []
        unavailable = find_unavailable_urls(unique_urls)
        state.mark_done("url_validation", unavailable_urls=sorted(unavailable))

    if unavailable:
        df_fixes = df_fixes.filter(~pl.col("repo_url").is_in(unavailable))

    # ------------------------------------------------------------------
    # Step 4: Commit traversal
    # ------------------------------------------------------------------
    if state.is_done("commit_collection"):
        logger.info("Step 4: Commit collection already done — skipping")
    else:
        logger.info("Step 4: Collecting commits …")
        # Pass already-done hashes so the step is also resumable mid-run
        done_hashes = stg.get_done_hashes(parquet_base)
        run_collection(
            df_fixes=df_fixes,
            blob_store=blob_store,
            staging_path=staging_path,
            num_workers=num_workers,
            already_done_hashes=done_hashes,
        )
        state.mark_done("commit_collection")

    # ------------------------------------------------------------------
    # Step 5: Repository metadata
    # ------------------------------------------------------------------
    if state.is_done("repo_metadata"):
        logger.info("Step 5: Repository metadata already done — skipping")
    else:
        logger.info("Step 5: Collecting repository metadata …")
        collect_repo_metadata(
            df_fixes=df_fixes,
            staging_path=staging_path,
            github_user=github_user,
            github_token=github_token,
        )
        # Persist fixes to staging for the writer
        fixes_stage = staging_path / "fixes_staging.parquet"
        df_fixes.write_parquet(fixes_stage, compression="zstd")
        state.mark_done("repo_metadata")

    # ------------------------------------------------------------------
    # Step 6: Finalize Parquet layout
    # ------------------------------------------------------------------
    if state.is_done("parquet_finalize"):
        logger.info("Step 6: Parquet finalization already done — skipping")
    else:
        logger.info("Step 6: Finalizing Parquet layout …")
        parquet_writer.finalize(base_path=parquet_base, clear_staging=True)
        state.mark_done("parquet_finalize")

    # ------------------------------------------------------------------
    # Step 7: DuckDB catalog (always rebuild — fast)
    # ------------------------------------------------------------------
    logger.info("Step 7: Building DuckDB catalog …")
    con = build_catalog(parquet_base, duckdb_path)
    con.close()

    # All steps done — remove checkpoint so next run starts fresh
    state.clear()

    elapsed = time.perf_counter() - t0
    logger.info(
        "=== Full collection complete in %.1f s (%.0f min) ===",
        elapsed, elapsed / 60,
    )
