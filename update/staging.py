"""
Staging helpers — utilities for reading from and managing the staging area.

The staging area lives at parquet/staging/ and supports two layouts:

Single-file (written directly by importers):
    staging/{table}_staging.parquet

Multi-file (written by append() for incremental collection):
    staging/{table}/part-{timestamp}.parquet
    staging/{table}/part-{timestamp}.parquet
    ...

Both layouts are readable by load() and the writer.  append() uses the
multi-file layout so each call is O(1) — no read+rewrite of existing data.
"""



import logging
import time
from pathlib import Path

import polars as pl

logger = logging.getLogger("cvefixes.staging")


def staging_file(base: Path, table: str) -> Path:
    """Single-file staging path (used by importers that write all at once)."""
    return base / "staging" / f"{table}_staging.parquet"


def staging_dir(base: Path, table: str) -> Path:
    """Multi-file staging directory (used by append())."""
    return base / "staging" / table


def exists(base: Path, table: str) -> bool:
    """Return True if any staging data exists for *table*."""
    single = staging_file(base, table)
    if single.exists() and single.stat().st_size > 0:
        return True
    d = staging_dir(base, table)
    return d.is_dir() and any(d.glob("*.parquet"))


def load(base: Path, table: str) -> pl.DataFrame | None:
    """Load all staging data for *table*, combining single-file and part files."""
    frames: list[pl.DataFrame] = []

    single = staging_file(base, table)
    if single.exists() and single.stat().st_size > 0:
        frames.append(pl.read_parquet(single))

    d = staging_dir(base, table)
    if d.is_dir():
        parts = sorted(d.glob("*.parquet"))
        for p in parts:
            if p.stat().st_size > 0:
                frames.append(pl.read_parquet(p))

    if not frames:
        return None
    if len(frames) == 1:
        return frames[0]
    return pl.concat(frames, how="diagonal")


def append(df: pl.DataFrame, base: Path, table: str) -> None:
    """
    Append *df* to the staging area for *table* by writing a new part file.

    Each call is O(1) — the existing staging files are never read.
    The writer globs all part files at finalization time.
    """
    part_dir = staging_dir(base, table)
    part_dir.mkdir(parents=True, exist_ok=True)
    # Use nanosecond timestamp to avoid collisions in concurrent scenarios
    part_file = part_dir / f"part-{time.time_ns()}.parquet"
    df.write_parquet(part_file, compression="zstd")
    logger.debug("Appended %d rows to %s staging (%s)", len(df), table, part_file.name)


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
