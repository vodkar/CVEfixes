"""
Optimization pass: promotes staging Parquet files into sorted, partitioned,
production Parquet files.

Staging Parquets are unordered flat files written during collection.
This module converts them to the final layout:

    parquet/metadata/          ← single sorted Parquet per metadata table
    parquet/file_change/       ← partitioned by programming_language
    parquet/method_change/     ← partitioned by language (from file_change join)

After a successful finalization the staging directory is cleared.
"""



import logging
import shutil
from pathlib import Path

import polars as pl

logger = logging.getLogger("cvefixes.writer")

_ZSTD_LEVEL = 3          # metadata + partitioned tables
_ROW_GROUP_SIZE = 128 * 1024 * 1024  # 128 MiB


def _staging_path(base: Path, name: str) -> Path:
    return base / "staging" / f"{name}_staging.parquet"


def _collect_staging_paths(base: Path, name: str) -> list[Path]:
    """Return all staging Parquet files for *name* (single-file or multi-file)."""
    paths: list[Path] = []
    single = base / "staging" / f"{name}_staging.parquet"
    if single.exists() and single.stat().st_size > 0:
        paths.append(single)
    multi_dir = base / "staging" / name
    if multi_dir.is_dir():
        paths.extend(sorted(p for p in multi_dir.glob("*.parquet") if p.stat().st_size > 0))
    return paths


def _exists(p: Path) -> bool:
    return p.exists() and p.stat().st_size > 0


def _staging_exists(base: Path, name: str) -> bool:
    return bool(_collect_staging_paths(base, name))


# ---------------------------------------------------------------------------
# Metadata tables (single sorted Parquet files)
# ---------------------------------------------------------------------------

def _finalize_cve(staging: Path, out: Path) -> None:
    paths = _collect_staging_paths(staging, "cve")
    if not paths:
        logger.warning("No CVE staging files — skipping")
        return
    (
        pl.scan_parquet([str(p) for p in paths])
        .sort("published_date", nulls_last=True)
        .collect()
        .write_parquet(out, compression="zstd", compression_level=_ZSTD_LEVEL)
    )
    logger.info("Wrote %s", out)


def _finalize_cwe(staging: Path, out_cwe: Path, out_class: Path) -> None:
    cwe_paths = _collect_staging_paths(staging, "cwe")
    class_paths = _collect_staging_paths(staging, "cwe_classification")
    if cwe_paths:
        pl.concat([pl.read_parquet(p) for p in cwe_paths]).sort("cwe_id").write_parquet(
            out_cwe, compression="zstd", compression_level=_ZSTD_LEVEL
        )
        logger.info("Wrote %s", out_cwe)
    if class_paths:
        pl.concat([pl.read_parquet(p) for p in class_paths]).sort(["cve_id", "cwe_id"]).write_parquet(
            out_class, compression="zstd", compression_level=_ZSTD_LEVEL
        )
        logger.info("Wrote %s", out_class)


def _finalize_repository(staging: Path, out: Path) -> None:
    paths = _collect_staging_paths(staging, "repository")
    if not paths:
        logger.warning("No repository staging file — skipping")
        return
    df = pl.concat([pl.read_parquet(p) for p in paths])
    # Assign integer repo_id keyed by sort order of url for stable IDs
    df = df.sort("repo_url").with_row_index("repo_id")
    df.write_parquet(out, compression="zstd", compression_level=_ZSTD_LEVEL)
    logger.info("Wrote %s", out)


def _finalize_commits(staging: Path, out: Path, repo_url_to_id: dict[str, int]) -> None:
    paths = _collect_staging_paths(staging, "commits")
    if not paths:
        logger.warning("No commits staging file — skipping")
        return
    df = pl.concat([pl.read_parquet(p) for p in paths])
    df = df.with_columns(
        pl.col("repo_url").replace_strict(repo_url_to_id, default=None).alias("repo_id").cast(pl.Int32)
    ).drop("repo_url")
    df = df.sort(["repo_id", "commit_date"], nulls_last=True)
    df.write_parquet(out, compression="zstd", compression_level=_ZSTD_LEVEL)
    logger.info("Wrote %s", out)


def _finalize_fixes(staging: Path, out: Path) -> None:
    paths = _collect_staging_paths(staging, "fixes")
    if not paths:
        logger.warning("No fixes staging file — skipping")
        return
    pl.concat([pl.read_parquet(p) for p in paths]).sort("cve_id").write_parquet(
        out, compression="zstd", compression_level=_ZSTD_LEVEL
    )
    logger.info("Wrote %s", out)


# ---------------------------------------------------------------------------
# Partitioned tables
# ---------------------------------------------------------------------------

def _write_partition(df: pl.DataFrame, out_dir: Path, lang: str) -> None:
    """Write a single language partition to disk."""
    part_dir = out_dir / f"language={lang}"
    part_dir.mkdir(parents=True, exist_ok=True)
    out = part_dir / "data.parquet"
    df.write_parquet(out, compression="zstd", compression_level=_ZSTD_LEVEL)


def _finalize_file_change(
    staging: Path,
    out_dir: Path,
    affected_languages: list[str] | None = None,
) -> None:
    paths = _collect_staging_paths(staging, "file_change")
    if not paths:
        logger.warning("No file_change staging files — skipping")
        return
    df = (
        pl.scan_parquet([str(p) for p in paths])
        .with_columns(pl.col("programming_language").fill_null("unknown"))
        .sort(["programming_language", "hash"])
        .collect()
    )
    for lang, group in df.group_by("programming_language"):
        lang_str = lang[0] if isinstance(lang, tuple) else str(lang)
        if affected_languages is not None and lang_str not in affected_languages:
            logger.debug("Skipping unaffected file_change partition: %s", lang_str)
            continue
        # Drop partition column before writing (hive partitioning adds it back)
        _write_partition(
            group.drop("programming_language"),
            out_dir,
            _safe_dirname(lang_str),
        )
    logger.info("Wrote file_change partitions to %s", out_dir)


def _finalize_method_change(
    staging: Path,
    out_dir: Path,
    file_change_parquet_dir: Path,
    affected_languages: list[str] | None = None,
) -> None:
    paths = _collect_staging_paths(staging, "method_change")
    if not paths:
        logger.warning("No method_change staging files — skipping")
        return

    # Join with file_change to inherit programming_language for partitioning
    # Use glob scan across all existing language partitions
    fc_glob = str(file_change_parquet_dir / "**" / "*.parquet")
    try:
        df_fc = pl.scan_parquet(fc_glob, hive_partitioning=True).select(
            ["file_change_id", "language"]  # hive adds 'language' from dir name
        )
    except Exception:
        # Fall back: no language info available — put everything in "unknown"
        df_fc = None

    df_mc = pl.scan_parquet([str(p) for p in paths]).sort("file_change_id").collect()

    if df_fc is not None:
        try:
            df_fc_collected = df_fc.collect()
            df_mc = df_mc.join(
                df_fc_collected.rename({"language": "programming_language"}),
                on="file_change_id",
                how="left",
            ).with_columns(
                pl.col("programming_language").fill_null("unknown")
            )
        except Exception as exc:
            logger.warning("Could not join method_change with language: %s", exc)
            df_mc = df_mc.with_columns(
                pl.lit("unknown").alias("programming_language")
            )
    else:
        df_mc = df_mc.with_columns(pl.lit("unknown").alias("programming_language"))

    for lang, group in df_mc.group_by("programming_language"):
        lang_str = lang[0] if isinstance(lang, tuple) else str(lang)
        if affected_languages is not None and lang_str not in affected_languages:
            logger.debug("Skipping unaffected method_change partition: %s", lang_str)
            continue
        _write_partition(
            group.drop("programming_language"),
            out_dir,
            _safe_dirname(lang_str),
        )
    logger.info("Wrote method_change partitions to %s", out_dir)


def _safe_dirname(lang: str) -> str:
    """Convert a language name to a filesystem-safe directory component."""
    return re.sub(r"[^\w\-.]", "_", lang) if lang else "unknown"


def _clear_staging(staging: Path) -> None:
    """Remove all staging Parquet files after successful finalization."""
    staging_dir = staging / "staging"
    if staging_dir.exists():
        shutil.rmtree(staging_dir)
        logger.info("Cleared staging directory %s", staging_dir)


# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------

def finalize(
    base_path: str | Path,
    affected_languages: list[str] | None = None,
    clear_staging: bool = True,
    skip_metadata: bool = False,
) -> None:
    """
    Promote staging Parquets into the final partitioned layout.

    Parameters
    ----------
    base_path:           root of the parquet/ tree  (i.e. ``parquet/``)
    affected_languages:  if provided, only re-write those language partitions
                         (used by incremental weekly update)
    clear_staging:       delete staging files after success (default True)
    skip_metadata:       if True, skip metadata table finalization; used by
                         run_weekly_update() which handles metadata via
                         _append_metadata() to preserve existing rows
    """
    import re  # local import so module-level _safe_dirname can use it lazily

    base = Path(base_path)
    staging = base  # staging lives at base/staging/
    metadata_dir = base / "metadata"
    file_change_dir = base / "file_change"
    method_change_dir = base / "method_change"

    metadata_dir.mkdir(parents=True, exist_ok=True)
    file_change_dir.mkdir(parents=True, exist_ok=True)
    method_change_dir.mkdir(parents=True, exist_ok=True)

    # --- Metadata tables ---
    if not skip_metadata:
        _finalize_cve(staging, metadata_dir / "cve.parquet")
        _finalize_cwe(staging, metadata_dir / "cwe.parquet", metadata_dir / "cwe_classification.parquet")

        df_repo = None
        if _staging_exists(staging, "repository"):
            _finalize_repository(staging, metadata_dir / "repository.parquet")
            df_repo = pl.read_parquet(metadata_dir / "repository.parquet")

        repo_url_to_id: dict[str, int] = {}
        if df_repo is not None and "repo_url" in df_repo.columns and "repo_id" in df_repo.columns:
            repo_url_to_id = dict(
                zip(df_repo["repo_url"].to_list(), df_repo["repo_id"].to_list())
            )

        _finalize_commits(staging, metadata_dir / "commits.parquet", repo_url_to_id)
        _finalize_fixes(staging, metadata_dir / "fixes.parquet")

    # --- Partitioned tables ---
    _finalize_file_change(staging, file_change_dir, affected_languages)
    _finalize_method_change(staging, method_change_dir, file_change_dir, affected_languages)

    if clear_staging:
        _clear_staging(staging)


# Make re available at module level for _safe_dirname
import re
