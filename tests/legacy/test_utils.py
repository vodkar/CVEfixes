"""
Tests for Code/utils.py

Covers:
- add_tbd_repos: placeholder repo row construction
- filter_non_textual: DataFrame filtering of binary/non-textual files
- prune_tables: end-to-end data integrity pruning on an in-memory SQLite DB
"""

import sqlite3

import pandas as pd
import pytest

from utils import add_tbd_repos, filter_non_textual, prune_tables


# ---------------------------------------------------------------------------
# add_tbd_repos
# ---------------------------------------------------------------------------

class TestAddTbdRepos:
    def test_single_repo(self):
        rows = add_tbd_repos(["https://github.com/foo/bar"])
        assert len(rows) == 1
        row = rows[0]
        assert row["repo_url"] == "https://github.com/foo/bar"
        assert row["owner"] == "foo"
        assert row["repo_name"] == "visit repo url"

    def test_multiple_repos(self):
        urls = ["https://github.com/a/b", "https://github.com/c/d"]
        rows = add_tbd_repos(urls)
        assert len(rows) == 2
        owners = {r["owner"] for r in rows}
        assert owners == {"a", "c"}

    def test_empty_list(self):
        assert add_tbd_repos([]) == []

    def test_url_without_slash_skipped(self):
        rows = add_tbd_repos(["noslash"])
        assert len(rows) == 0

    def test_all_placeholder_fields_present(self):
        rows = add_tbd_repos(["https://github.com/foo/bar"])
        expected_keys = {
            "repo_url", "repo_name", "description", "date_created",
            "date_last_push", "homepage", "repo_language",
            "forks_count", "stars_count", "owner",
        }
        assert set(rows[0].keys()) == expected_keys

    def test_owner_extracted_correctly(self):
        rows = add_tbd_repos(["https://github.com/myorg/myrepo"])
        assert rows[0]["owner"] == "myorg"


# ---------------------------------------------------------------------------
# filter_non_textual
# ---------------------------------------------------------------------------

def _file_df(rows):
    return pd.DataFrame(rows)


class TestFilterNonTextual:
    def test_removes_zero_line_files(self):
        df = _file_df([
            {"file_change_id": "1", "num_lines_added": "0", "num_lines_deleted": "0"},
            {"file_change_id": "2", "num_lines_added": "5", "num_lines_deleted": "0"},
        ])
        result = filter_non_textual(df)
        assert "1" not in result["file_change_id"].values
        assert "2" in result["file_change_id"].values

    def test_keeps_files_with_additions_only(self):
        df = _file_df([
            {"file_change_id": "A", "num_lines_added": "10", "num_lines_deleted": "0"},
        ])
        result = filter_non_textual(df)
        assert len(result) == 1

    def test_keeps_files_with_deletions_only(self):
        df = _file_df([
            {"file_change_id": "B", "num_lines_added": "0", "num_lines_deleted": "3"},
        ])
        result = filter_non_textual(df)
        assert len(result) == 1

    def test_empty_dataframe(self):
        df = pd.DataFrame({"file_change_id": [], "num_lines_added": [], "num_lines_deleted": []})
        result = filter_non_textual(df)
        assert len(result) == 0

    def test_all_non_textual_removed(self):
        df = _file_df([
            {"file_change_id": str(i), "num_lines_added": "0", "num_lines_deleted": "0"}
            for i in range(5)
        ])
        result = filter_non_textual(df)
        assert len(result) == 0

    def test_index_reset(self):
        df = _file_df([
            {"file_change_id": "1", "num_lines_added": "0", "num_lines_deleted": "0"},
            {"file_change_id": "2", "num_lines_added": "5", "num_lines_deleted": "0"},
            {"file_change_id": "3", "num_lines_added": "0", "num_lines_deleted": "0"},
        ])
        result = filter_non_textual(df)
        assert list(result.index) == list(range(len(result)))


# ---------------------------------------------------------------------------
# prune_tables
# ---------------------------------------------------------------------------

def _populate_db(conn, *, with_method=True, with_repo=True):
    """
    Insert a minimal but complete set of linked rows into *conn*
    that should all survive pruning.
    """
    # cve
    conn.execute(
        "INSERT INTO cve VALUES (?,?,?,?,?)",
        ("CVE-2021-0001", "2021-01-01", "Buffer overflow",
         '[{"url":"https://github.com/foo/bar/commit/abc123def456"}]',
         '[{"description":[{"lang":"en","value":"CWE-119"}]}]'),
    )
    # fixes — long hash matching commits.hash
    conn.execute(
        "INSERT INTO fixes VALUES (?,?,?)",
        ("CVE-2021-0001", "abc123def456abc123def456abc123def456abc1", "https://github.com/foo/bar"),
    )
    # commits — same long hash
    conn.execute(
        "INSERT INTO commits VALUES (?,?,?,?,?,?,?,?)",
        ("abc123def456abc123def456abc123def456abc1",
         "https://github.com/foo/bar",
         "Alice", "2021-01-01", "10", "5", "0.5", "0.3"),
    )
    if with_repo:
        conn.execute(
            "INSERT INTO repository VALUES (?,?,?,?,?,?,?)",
            ("https://github.com/foo/bar", "foo/bar", "A project", "2019-01-01", "foo", "50", "5"),
        )
    # file_change
    conn.execute(
        "INSERT INTO file_change VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        ("fc1", "abc123def456abc123def456abc123def456abc1",
         "vuln.c", "C", "10", "5", "old code", "new code", "@@ -1,5 +1,5 @@", "50", "8", "100"),
    )
    if with_method:
        conn.execute(
            "INSERT INTO method_change VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            ("mc1", "fc1", "parse_input", "void parse_input(char*)",
             "10", "25", "int x = buf[n];", "15", "8", "40", "True"),
        )
    # cwe
    conn.execute("INSERT INTO cwe VALUES (?,?,?)", ("CWE-119", "Buffer Errors", "desc"))
    conn.execute("INSERT INTO cwe VALUES (?,?,?)", ("NVD-CWE-noinfo", "No Info", "desc"))
    # cwe_classification
    conn.execute("INSERT INTO cwe_classification VALUES (?,?)", ("CVE-2021-0001", "CWE-119"))
    conn.commit()


_PANDAS_APPEND_XFAIL = pytest.mark.xfail(
    strict=True,
    reason="prune_tables() uses DataFrame.append() which was removed in "
           "pandas 2.0. Original code requires pandas ~1.2.",
)


@_PANDAS_APPEND_XFAIL
class TestPruneTables:
    def test_valid_data_survives_pruning(self, tmp_path):
        from tests.legacy.conftest import make_file_db
        db_file = tmp_path / "test.db"
        conn = make_file_db(db_file)
        _populate_db(conn)
        conn.close()

        prune_tables(db_file)

        # Verify data survived
        verify = sqlite3.connect(str(db_file))
        rows = verify.execute("SELECT cve_id FROM cve").fetchall()
        assert len(rows) == 1
        assert rows[0][0] == "CVE-2021-0001"
        verify.close()

    def test_orphaned_commit_removed(self, tmp_path):
        """A commit not referenced in fixes must be removed by pruning."""
        from tests.legacy.conftest import make_file_db
        db_file = tmp_path / "test.db"
        conn = make_file_db(db_file)
        _populate_db(conn)
        # Add an orphaned commit (no matching fixes row)
        conn.execute(
            "INSERT INTO commits VALUES (?,?,?,?,?,?,?,?)",
            ("orphan_hash_000000000000000000000000000000000000",
             "https://github.com/foo/bar",
             "Eve", "2021-02-01", "3", "1", "0.1", "0.2"),
        )
        conn.commit()
        conn.close()

        prune_tables(db_file)

        verify = sqlite3.connect(str(db_file))
        hashes = [r[0] for r in verify.execute("SELECT hash FROM commits").fetchall()]
        assert "orphan_hash_000000000000000000000000000000000000" not in hashes
        verify.close()

    def test_non_textual_file_removed(self, tmp_path):
        """Files with 0 added + 0 deleted lines must be pruned."""
        from tests.legacy.conftest import make_file_db
        db_file = tmp_path / "test.db"
        conn = make_file_db(db_file)
        _populate_db(conn, with_method=False)
        # Replace file with 0-line change (binary file)
        conn.execute("DELETE FROM file_change WHERE file_change_id = 'fc1'")
        conn.execute(
            "INSERT INTO file_change VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            ("fc_binary", "abc123def456abc123def456abc123def456abc1",
             "binary.png", "unknown", "0", "0", None, None, None, None, None, None),
        )
        conn.commit()
        conn.close()

        prune_tables(db_file)

        verify = sqlite3.connect(str(db_file))
        fc_ids = [r[0] for r in verify.execute("SELECT file_change_id FROM file_change").fetchall()]
        assert "fc_binary" not in fc_ids
        verify.close()

    def test_unnamed_method_removed(self, tmp_path):
        """Method rows with empty name must be removed."""
        from tests.legacy.conftest import make_file_db
        db_file = tmp_path / "test.db"
        conn = make_file_db(db_file)
        _populate_db(conn)
        # Add a method with empty name
        conn.execute(
            "INSERT INTO method_change VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            ("mc_empty", "fc1", "", "void ()",
             "30", "40", "code here", "10", "2", "20", "True"),
        )
        conn.commit()
        conn.close()

        prune_tables(db_file)

        verify = sqlite3.connect(str(db_file))
        method_ids = [r[0] for r in verify.execute("SELECT method_change_id FROM method_change").fetchall()]
        assert "mc_empty" not in method_ids
        verify.close()
