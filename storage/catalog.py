"""
DuckDB catalog layer — creates and maintains cvefixes.duckdb.

The DuckDB file contains ONLY views pointing to Parquet files on disk.
No data is stored inside the DuckDB file itself.

Views registered:
    cve, cwe, cwe_classification, repository, commits, fixes
    file_change          (hive-partitioned by language)
    method_change        (hive-partitioned by language)
"""



import logging
from pathlib import Path

import duckdb

logger = logging.getLogger("cvefixes.catalog")

_METADATA_TABLES = [
    "cve",
    "cwe",
    "cwe_classification",
    "repository",
    "commits",
    "fixes",
]


def build_catalog(
    parquet_base: str | Path,
    duckdb_path: str | Path,
) -> duckdb.DuckDBPyConnection:
    """
    (Re)create all views in *duckdb_path* pointing to Parquet files under
    *parquet_base*.

    Safe to call repeatedly — all views are CREATE OR REPLACE.

    Parameters
    ----------
    parquet_base: root of the parquet/ tree (e.g. ``parquet/``)
    duckdb_path:  path to the .duckdb catalog file

    Returns
    -------
    Open DuckDB connection (caller should close when done).
    """
    parquet_base = Path(parquet_base).resolve()
    duckdb_path = Path(duckdb_path)
    duckdb_path.parent.mkdir(parents=True, exist_ok=True)

    con = duckdb.connect(str(duckdb_path))

    # Metadata tables — single Parquet files
    for table in _METADATA_TABLES:
        parquet_file = parquet_base / "metadata" / f"{table}.parquet"
        if not parquet_file.exists():
            logger.warning("Metadata file missing, skipping view: %s", parquet_file)
            continue
        con.execute(f"""
            CREATE OR REPLACE VIEW {table} AS
            SELECT * FROM read_parquet('{parquet_file}')
        """)
        logger.debug("Registered view: %s → %s", table, parquet_file)

    # Partitioned tables — hive-style directories
    for table in ("file_change", "method_change"):
        glob = parquet_base / table / "**" / "*.parquet"
        part_dir = parquet_base / table
        if not part_dir.exists() or not list(part_dir.rglob("*.parquet")):
            logger.warning("No partitioned data found for %s — skipping view", table)
            continue
        con.execute(f"""
            CREATE OR REPLACE VIEW {table} AS
            SELECT * FROM read_parquet('{glob}', hive_partitioning=true)
        """)
        logger.debug("Registered partitioned view: %s → %s", table, glob)

    # Collect statistics for better query planning
    con.execute("ANALYZE")
    logger.info("DuckDB catalog built at %s", duckdb_path)
    return con


def open_catalog(duckdb_path: str | Path) -> duckdb.DuckDBPyConnection:
    """
    Open an existing DuckDB catalog for querying.

    The connection is read-only to prevent accidental writes.
    """
    return duckdb.connect(str(duckdb_path), read_only=True)


def get_table_stats(con: duckdb.DuckDBPyConnection) -> dict[str, int]:
    """
    Return a dict of {table_name: row_count} for all registered views.

    Useful for regression testing and monitoring.
    """
    views = con.execute(
        "SELECT table_name FROM information_schema.tables WHERE table_type = 'VIEW'"
    ).fetchall()
    stats: dict[str, int] = {}
    for (view_name,) in views:
        try:
            count = con.execute(f"SELECT count(*) FROM {view_name}").fetchone()[0]
            stats[view_name] = count
        except Exception as exc:
            logger.warning("Could not count rows in %s: %s", view_name, exc)
            stats[view_name] = -1
    return stats
