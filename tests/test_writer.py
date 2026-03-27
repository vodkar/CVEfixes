"""
Unit tests for storage/writer.py

Tests the optimization pass that converts flat staging Parquets into
sorted, partitioned production Parquets.
"""

import polars as pl
import pytest

from storage import writer as parquet_writer


def _write_staging(base, table, rows):
    import polars as pl
    staging_dir = base / "staging"
    staging_dir.mkdir(parents=True, exist_ok=True)
    df = pl.DataFrame(rows)
    df.write_parquet(staging_dir / f"{table}_staging.parquet", compression="zstd")
    return df


class TestFinalizeMetadata:
    def test_cve_sorted_by_date(self, tmp_path):
        import datetime
        rows = [
            {"cve_id": "CVE-2022-1", "published_date": datetime.date(2022, 3, 1),
             "severity_v2": None, "severity_v3": 7.5, "description": "d1",
             "reference_json": "[]", "problemtype_json": "[]"},
            {"cve_id": "CVE-2020-1", "published_date": datetime.date(2020, 1, 15),
             "severity_v2": 5.0, "severity_v3": None, "description": "d2",
             "reference_json": "[]", "problemtype_json": "[]"},
        ]
        _write_staging(tmp_path / "parquet", "cve", rows)
        parquet_writer.finalize(tmp_path / "parquet", clear_staging=False)

        out = tmp_path / "parquet" / "metadata" / "cve.parquet"
        assert out.exists()
        df = pl.read_parquet(out)
        dates = df["published_date"].to_list()
        assert dates == sorted(dates, key=lambda d: (d is None, d))

    def test_fixes_written(self, tmp_path):
        rows = [
            {"cve_id": "CVE-2021-5", "hash": "aaa"},
            {"cve_id": "CVE-2021-3", "hash": "bbb"},
        ]
        _write_staging(tmp_path / "parquet", "fixes", rows)
        parquet_writer.finalize(tmp_path / "parquet", clear_staging=False)

        out = tmp_path / "parquet" / "metadata" / "fixes.parquet"
        assert out.exists()
        df = pl.read_parquet(out)
        assert set(df["cve_id"].to_list()) == {"CVE-2021-5", "CVE-2021-3"}


class TestFinalizePartitioned:
    def test_file_change_partitioned_by_language(self, tmp_path):
        rows = [
            {"file_change_id": 1, "hash": "h1", "filename": "a.c",
             "programming_language": "C", "num_lines_added": 5,
             "num_lines_deleted": 2, "code_before_hash": None,
             "diff": None, "nloc": 10, "complexity": 2},
            {"file_change_id": 2, "hash": "h2", "filename": "b.py",
             "programming_language": "Python", "num_lines_added": 3,
             "num_lines_deleted": 1, "code_before_hash": None,
             "diff": None, "nloc": 8, "complexity": 1},
            {"file_change_id": 3, "hash": "h3", "filename": "c.c",
             "programming_language": "C", "num_lines_added": 7,
             "num_lines_deleted": 0, "code_before_hash": None,
             "diff": None, "nloc": 20, "complexity": 5},
        ]
        _write_staging(tmp_path / "parquet", "file_change", rows)
        parquet_writer.finalize(tmp_path / "parquet", clear_staging=False)

        c_dir = tmp_path / "parquet" / "file_change" / "language=C"
        py_dir = tmp_path / "parquet" / "file_change" / "language=Python"
        assert c_dir.exists()
        assert py_dir.exists()

        df_c = pl.read_parquet(c_dir / "data.parquet")
        df_py = pl.read_parquet(py_dir / "data.parquet")
        assert len(df_c) == 2
        assert len(df_py) == 1

    def test_clear_staging_removes_files(self, tmp_path):
        rows = [{"cve_id": "CVE-2021-1", "published_date": None,
                 "severity_v2": None, "severity_v3": None, "description": "x",
                 "reference_json": "[]", "problemtype_json": "[]"}]
        _write_staging(tmp_path / "parquet", "cve", rows)
        staging_file = tmp_path / "parquet" / "staging" / "cve_staging.parquet"
        assert staging_file.exists()
        parquet_writer.finalize(tmp_path / "parquet", clear_staging=True)
        assert not staging_file.exists()
