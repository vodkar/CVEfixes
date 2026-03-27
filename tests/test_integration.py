"""
Integration tests — run the NVD importer, CWE importer, writer, and catalog
on a small synthetic dataset without hitting external services.

These tests use mocked/synthetic data to verify the end-to-end pipeline
produces the correct Parquet files and DuckDB views.
"""

from __future__ import annotations

import datetime
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import polars as pl
import pytest

from storage.blob_store import BlobStore
from storage.catalog import build_catalog, get_table_stats
from storage import writer as parquet_writer


# ---------------------------------------------------------------------------
# Helpers to build synthetic staging data
# ---------------------------------------------------------------------------

def _write_staging(parquet_base: Path, table: str, rows: list[dict]) -> None:
    staging = parquet_base / "staging"
    staging.mkdir(parents=True, exist_ok=True)
    pl.DataFrame(rows).write_parquet(
        staging / f"{table}_staging.parquet", compression="zstd"
    )


def _build_synthetic_staging(parquet_base: Path) -> None:
    """Populate all staging tables with synthetic rows."""
    import datetime

    _write_staging(parquet_base, "cve", [
        {"cve_id": "CVE-2021-0001", "published_date": datetime.date(2021, 1, 15),
         "severity_v2": 5.0, "severity_v3": 7.5, "description": "Buffer overflow",
         "reference_json": json.dumps([{"url": "https://github.com/foo/bar/commit/abc123"}]),
         "problemtype_json": json.dumps([{"description": [{"value": "CWE-119"}]}])},
        {"cve_id": "CVE-2021-0002", "published_date": datetime.date(2021, 6, 10),
         "severity_v2": 3.5, "severity_v3": 6.1, "description": "SQL injection",
         "reference_json": json.dumps([{"url": "https://github.com/bar/baz/commit/def456"}]),
         "problemtype_json": json.dumps([{"description": [{"value": "CWE-89"}]}])},
    ])

    _write_staging(parquet_base, "fixes", [
        {"cve_id": "CVE-2021-0001", "hash": "abc123", "repo_url": "https://github.com/foo/bar"},
        {"cve_id": "CVE-2021-0002", "hash": "def456", "repo_url": "https://github.com/bar/baz"},
    ])

    _write_staging(parquet_base, "cwe", [
        {"cwe_id": "CWE-119", "cwe_name": "Buffer Errors",
         "description": "Buffer errors", "extended_description": "",
         "url": "https://cwe.mitre.org/data/definitions/119.html", "is_category": False},
        {"cwe_id": "CWE-89", "cwe_name": "SQL Injection",
         "description": "SQL injection", "extended_description": "",
         "url": "https://cwe.mitre.org/data/definitions/89.html", "is_category": False},
        {"cwe_id": "NVD-CWE-noinfo", "cwe_name": "Insufficient Information",
         "description": "No info", "extended_description": "",
         "url": "https://nvd.nist.gov/vuln/categories", "is_category": False},
    ])

    _write_staging(parquet_base, "cwe_classification", [
        {"cve_id": "CVE-2021-0001", "cwe_id": "CWE-119"},
        {"cve_id": "CVE-2021-0002", "cwe_id": "CWE-89"},
    ])

    _write_staging(parquet_base, "repository", [
        {"repo_url": "https://github.com/bar/baz",
         "repo_name": "bar/baz", "description": "A project",
         "date_created": "2019-01-01", "date_last_push": "2021-06-10",
         "homepage": None, "repo_language": "Python",
         "owner": "bar", "forks_count": 10, "stars_count": 100},
        {"repo_url": "https://github.com/foo/bar",
         "repo_name": "foo/bar", "description": "Another project",
         "date_created": "2018-05-01", "date_last_push": "2021-01-15",
         "homepage": None, "repo_language": "C",
         "owner": "foo", "forks_count": 5, "stars_count": 50},
    ])

    _write_staging(parquet_base, "commits", [
        {"hash": "abc123", "repo_url": "https://github.com/foo/bar",
         "author": "Alice", "commit_date": datetime.datetime(2021, 1, 15, 12, 0),
         "dmm_unit_size": 0.5, "dmm_unit_complexity": 0.3,
         "num_lines_added": 10, "num_lines_deleted": 5},
        {"hash": "def456", "repo_url": "https://github.com/bar/baz",
         "author": "Bob", "commit_date": datetime.datetime(2021, 6, 10, 8, 30),
         "dmm_unit_size": 0.7, "dmm_unit_complexity": 0.4,
         "num_lines_added": 20, "num_lines_deleted": 3},
    ])

    _write_staging(parquet_base, "file_change", [
        {"file_change_id": 1, "hash": "abc123", "filename": "vuln.c",
         "programming_language": "C", "num_lines_added": 10, "num_lines_deleted": 5,
         "code_before_hash": None, "diff": None, "nloc": 50, "complexity": 8},
        {"file_change_id": 2, "hash": "def456", "filename": "query.py",
         "programming_language": "Python", "num_lines_added": 20, "num_lines_deleted": 3,
         "code_before_hash": None, "diff": None, "nloc": 30, "complexity": 4},
    ])

    _write_staging(parquet_base, "method_change", [
        {"method_change_id": 101, "file_change_id": 1, "name": "parse_input",
         "signature": "void parse_input(char*)", "start_line": 10, "end_line": 25,
         "before_change": True, "cyclomatic_complexity": 5, "nloc": 15, "token_count": 40},
        {"method_change_id": 102, "file_change_id": 2, "name": "run_query",
         "signature": "run_query(sql)", "start_line": 5, "end_line": 18,
         "before_change": True, "cyclomatic_complexity": 3, "nloc": 13, "token_count": 35},
    ])


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestEndToEndPipeline:
    def test_finalize_produces_metadata_files(self, tmp_path):
        parquet_base = tmp_path / "parquet"
        _build_synthetic_staging(parquet_base)
        parquet_writer.finalize(parquet_base, clear_staging=False)

        metadata = parquet_base / "metadata"
        assert (metadata / "cve.parquet").exists()
        assert (metadata / "fixes.parquet").exists()
        assert (metadata / "cwe.parquet").exists()
        assert (metadata / "cwe_classification.parquet").exists()

    def test_finalize_produces_language_partitions(self, tmp_path):
        parquet_base = tmp_path / "parquet"
        _build_synthetic_staging(parquet_base)
        parquet_writer.finalize(parquet_base, clear_staging=False)

        fc = parquet_base / "file_change"
        assert (fc / "language=C").exists()
        assert (fc / "language=Python").exists()

    def test_catalog_views_queryable(self, tmp_path):
        parquet_base = tmp_path / "parquet"
        _build_synthetic_staging(parquet_base)
        parquet_writer.finalize(parquet_base, clear_staging=False)

        con = build_catalog(parquet_base, tmp_path / "cvefixes.duckdb")
        try:
            stats = get_table_stats(con)
            assert stats.get("cve", 0) == 2
            assert stats.get("fixes", 0) == 2
            assert stats.get("cwe", 0) == 3
        finally:
            con.close()

    def test_cve_sorted_by_date(self, tmp_path):
        parquet_base = tmp_path / "parquet"
        _build_synthetic_staging(parquet_base)
        parquet_writer.finalize(parquet_base, clear_staging=False)

        df = pl.read_parquet(parquet_base / "metadata" / "cve.parquet")
        if "published_date" in df.columns:
            dates = df["published_date"].drop_nulls().to_list()
            assert dates == sorted(dates)

    def test_file_change_row_counts(self, tmp_path):
        parquet_base = tmp_path / "parquet"
        _build_synthetic_staging(parquet_base)
        parquet_writer.finalize(parquet_base, clear_staging=False)

        c_dir = parquet_base / "file_change" / "language=C"
        py_dir = parquet_base / "file_change" / "language=Python"
        assert len(pl.read_parquet(c_dir / "data.parquet")) == 1
        assert len(pl.read_parquet(py_dir / "data.parquet")) == 1

    def test_staging_cleared_after_finalize(self, tmp_path):
        parquet_base = tmp_path / "parquet"
        _build_synthetic_staging(parquet_base)
        parquet_writer.finalize(parquet_base, clear_staging=True)

        staging = parquet_base / "staging"
        assert not staging.exists() or not list(staging.glob("*.parquet"))

    def test_duckdb_sql_join(self, tmp_path):
        """Verify that a basic SQL join across views works correctly."""
        parquet_base = tmp_path / "parquet"
        _build_synthetic_staging(parquet_base)
        parquet_writer.finalize(parquet_base, clear_staging=False)

        con = build_catalog(parquet_base, tmp_path / "cvefixes.duckdb")
        try:
            result = con.execute("""
                SELECT c.cve_id, f.hash
                FROM cve c
                JOIN fixes f ON c.cve_id = f.cve_id
                ORDER BY c.cve_id
            """).fetchall()
            assert len(result) == 2
            assert result[0][0] == "CVE-2021-0001"
            assert result[1][0] == "CVE-2021-0002"
        finally:
            con.close()


class TestBlobStoreIntegration:
    def test_code_before_reconstructable(self, tmp_path):
        """Write source code to blob store, verify method lines are recoverable."""
        store = BlobStore(tmp_path / "blobs")
        source = "\n".join([f"line {i}" for i in range(1, 21)])  # 20 lines
        digest = store.write(source.encode())

        # Simulate method at lines 5-10
        reconstructed = store.read_lines(digest, 5, 10)
        expected_lines = [f"line {i}" for i in range(5, 11)]
        assert reconstructed == "\n".join(expected_lines)

    def test_dedup_across_multiple_cves(self, tmp_path):
        """Same file touched by multiple CVEs should be stored only once."""
        store = BlobStore(tmp_path / "blobs")
        shared_source = b"int main() { return 0; }"

        hashes = [store.write(shared_source) for _ in range(10)]
        assert len(set(hashes)) == 1  # all the same hash
        assert store.stats()["blob_count"] == 1
