"""
Staging helpers — utilities for reading from and managing the staging area.

The staging area lives at:
    parquet/staging/
        cve_staging.parquet
        fixes_staging.parquet
        cwe_staging.parquet
        cwe_classification_staging.parquet
        repository_staging.parquet
        commits_staging.parquet
        file_change_staging.parquet
        method_change_staging.parquet
"""

from __future__ import annotations

import logging
from pathlib import Path

import polars as pl

logger = logging.getLogger("cvefixes.staging")


def staging_file(base: Path, table: str) -> Path:
    return base / "staging" / f"{table}_staging.parquet"


def exists(base: Path, table: str) -> bool:
    p = staging_file(base, table)
    return p.exists() and p.stat().st_size > 0


def load(base: Path, table: str) -> pl.DataFrame | None:
    p = staging_file(base, table)
    if not p.exists():
        return None
    return pl.read_parquet(p)


def append(df: pl.DataFrame, base: Path, table: str) -> None:
    """Append *df* to the staging Parquet for *table* (or create it)."""
    p = staging_file(base, table)
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.exists():
        existing = pl.read_parquet(p)
        df = pl.concat([existing, df])
    df.write_parquet(p, compression="zstd")
    logger.debug("Staging %s now has %d rows", table, len(df))


def get_done_hashes(base: Path) -> set[str]:
    """
    Return the set of commit hashes that are already in the commits staging file.
    Used by incremental collection to skip already-processed commits.
    """
    df = load(base, "commits")
    if df is None or "hash" not in df.columns:
        return set()
    return set(df["hash"].to_list())


def get_affected_languages(base: Path) -> list[str]:
    """
    Return the list of programming_language values present in the
    file_change staging file.  Used by the merger to know which partitions
    need to be rewritten.
    """
    df = load(base, "file_change")
    if df is None or "programming_language" not in df.columns:
        return []
    return (
        df["programming_language"]
        .drop_nulls()
        .unique()
        .to_list()
    )
