"""
Regression tests — verify that row counts only increase and no existing rows
are mutated after an incremental update.

These tests simulate two collection runs:
1. Initial run → writes production Parquets
2. Incremental update → appends new rows

Invariants checked:
- Total row counts only increase
- All rows present after run 1 are still present after run 2
- Blob store dedup ratio is tracked
"""

import polars as pl
import pytest

from storage.blob_store import BlobStore
from storage.catalog import build_catalog, get_table_stats


def _write_production(parquet_base, table, rows):
    meta_dir = parquet_base / "metadata"
    meta_dir.mkdir(parents=True, exist_ok=True)
    pl.DataFrame(rows).write_parquet(meta_dir / f"{table}.parquet", compression="zstd")


def _append_production(parquet_base, table, new_rows):
    """Append new rows to existing production Parquet (simulates incremental update)."""
    meta_dir = parquet_base / "metadata"
    p = meta_dir / f"{table}.parquet"
    existing = pl.read_parquet(p) if p.exists() else pl.DataFrame()
    combined = pl.concat([existing, pl.DataFrame(new_rows)])
    combined.write_parquet(p, compression="zstd")


class TestRowCountsOnlyIncrease:
    def test_metadata_counts_increase(self, tmp_path):
        parquet_base = tmp_path / "parquet"

        # Run 1: initial data
        _write_production(parquet_base, "cve", [
            {"cve_id": "CVE-2021-1"},
            {"cve_id": "CVE-2021-2"},
        ])
        con1 = build_catalog(parquet_base, tmp_path / "cat.duckdb")
        stats1 = get_table_stats(con1)
        con1.close()

        # Run 2: incremental — add new CVE
        _append_production(parquet_base, "cve", [{"cve_id": "CVE-2022-1"}])
        con2 = build_catalog(parquet_base, tmp_path / "cat.duckdb")
        stats2 = get_table_stats(con2)
        con2.close()

        assert stats2["cve"] >= stats1["cve"], (
            f"CVE count decreased: {stats1['cve']} → {stats2['cve']}"
        )
        assert stats2["cve"] == 3


class TestNoExistingRowsMutated:
    def test_original_rows_survive_append(self, tmp_path):
        parquet_base = tmp_path / "parquet"

        original_rows = [
            {"cve_id": "CVE-ORIG-1", "description": "original description"},
            {"cve_id": "CVE-ORIG-2", "description": "another original"},
        ]
        _write_production(parquet_base, "cve", original_rows)

        # Incremental update
        _append_production(parquet_base, "cve", [
            {"cve_id": "CVE-NEW-1", "description": "new entry"}
        ])

        df = pl.read_parquet(parquet_base / "metadata" / "cve.parquet")
        orig_ids = {"CVE-ORIG-1", "CVE-ORIG-2"}
        remaining_ids = set(df["cve_id"].to_list())
        assert orig_ids.issubset(remaining_ids), "Original CVE IDs were removed"

        # Check descriptions were not altered
        for row in original_rows:
            if "description" in df.columns:
                matches = df.filter(pl.col("cve_id") == row["cve_id"])
                if len(matches) > 0:
                    assert matches["description"][0] == row["description"]


class TestBlobStoreDedup:
    def test_dedup_ratio_tracked(self, tmp_path):
        store = BlobStore(root=tmp_path / "blobs")

        # Write 10 blobs, 5 unique
        unique_content = [f"content_{i}".encode() for i in range(5)]
        write_count = 0
        for content in unique_content * 2:
            store.write(content)
            write_count += 1

        stats = store.stats()
        assert stats["blob_count"] == 5  # only 5 unique blobs stored
        dedup_ratio = 1.0 - (stats["blob_count"] / write_count)
        assert dedup_ratio == pytest.approx(0.5)  # 50% deduplication


class TestPartitionedTableMonotonicity:
    def test_file_change_partition_count_increases(self, tmp_path):
        parquet_base = tmp_path / "parquet"

        # Run 1: C partition only
        c_dir = parquet_base / "file_change" / "language=C"
        c_dir.mkdir(parents=True, exist_ok=True)
        pl.DataFrame({"file_change_id": [1], "hash": ["h1"]}).write_parquet(
            c_dir / "data.parquet"
        )

        con1 = build_catalog(parquet_base, tmp_path / "cat.duckdb")
        count1 = con1.execute("SELECT count(*) FROM file_change").fetchone()[0]
        con1.close()

        # Run 2: add Python partition
        py_dir = parquet_base / "file_change" / "language=Python"
        py_dir.mkdir(parents=True, exist_ok=True)
        pl.DataFrame({"file_change_id": [2, 3], "hash": ["h2", "h3"]}).write_parquet(
            py_dir / "data.parquet"
        )

        con2 = build_catalog(parquet_base, tmp_path / "cat.duckdb")
        count2 = con2.execute("SELECT count(*) FROM file_change").fetchone()[0]
        con2.close()

        assert count2 > count1
        assert count2 == 3
