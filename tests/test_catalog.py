"""
Unit tests for storage/catalog.py

Tests DuckDB view registration and basic query correctness.
"""

import polars as pl
import pytest

from storage.catalog import build_catalog, get_table_stats


def _write_metadata(parquet_base, table, rows):
    meta_dir = parquet_base / "metadata"
    meta_dir.mkdir(parents=True, exist_ok=True)
    pl.DataFrame(rows).write_parquet(meta_dir / f"{table}.parquet", compression="zstd")


class TestBuildCatalog:
    def test_catalog_creates_views(self, tmp_path):
        parquet_base = tmp_path / "parquet"
        _write_metadata(parquet_base, "cve", [
            {"cve_id": "CVE-2021-1", "description": "test"}
        ])
        con = build_catalog(parquet_base, tmp_path / "test.duckdb")
        result = con.execute("SELECT cve_id FROM cve").fetchall()
        assert result == [("CVE-2021-1",)]
        con.close()

    def test_catalog_file_created(self, tmp_path):
        parquet_base = tmp_path / "parquet"
        _write_metadata(parquet_base, "fixes", [
            {"cve_id": "CVE-2021-1", "hash": "abc"}
        ])
        duckdb_path = tmp_path / "cvefixes.duckdb"
        con = build_catalog(parquet_base, duckdb_path)
        con.close()
        assert duckdb_path.exists()

    def test_missing_table_skipped_gracefully(self, tmp_path):
        parquet_base = tmp_path / "parquet"
        # No metadata files at all — should not raise
        con = build_catalog(parquet_base, tmp_path / "empty.duckdb")
        con.close()

    def test_partitioned_view(self, tmp_path):
        parquet_base = tmp_path / "parquet"
        fc_dir = parquet_base / "file_change" / "language=Python"
        fc_dir.mkdir(parents=True, exist_ok=True)
        pl.DataFrame({"file_change_id": [1, 2], "hash": ["h1", "h2"]}).write_parquet(
            fc_dir / "data.parquet"
        )
        con = build_catalog(parquet_base, tmp_path / "cat.duckdb")
        count = con.execute("SELECT count(*) FROM file_change").fetchone()[0]
        assert count == 2
        con.close()


class TestGetTableStats:
    def test_returns_counts(self, tmp_path):
        parquet_base = tmp_path / "parquet"
        _write_metadata(parquet_base, "cve", [
            {"cve_id": "CVE-A"}, {"cve_id": "CVE-B"}
        ])
        con = build_catalog(parquet_base, tmp_path / "stats.duckdb")
        stats = get_table_stats(con)
        con.close()
        assert stats["cve"] == 2
