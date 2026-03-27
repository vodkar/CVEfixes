"""
Tests for Code/database.py

Covers:
- create_connection: connects to a database file
- table_exists: detects presence/absence of tables
- fetchone_query: checks for record existence by column value

Note: database.py uses a module-level `conn` global for some functions.
We test via direct sqlite3 connections here to avoid global state coupling.
"""

import sqlite3
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# Ensure Code/ is importable (handled by conftest, but be safe)
CODE = Path(__file__).parent.parent.parent / "Code"
if str(CODE) not in sys.path:
    sys.path.insert(0, str(CODE))

import database as db


# ---------------------------------------------------------------------------
# create_connection
# ---------------------------------------------------------------------------

class TestCreateConnection:
    def test_creates_connection_to_file(self, tmp_path):
        db_path = tmp_path / "test.db"
        conn = db.create_connection(str(db_path))
        assert conn is not None
        conn.close()

    def test_returns_sqlite_connection(self, tmp_path):
        db_path = tmp_path / "test.db"
        conn = db.create_connection(str(db_path))
        assert isinstance(conn, sqlite3.Connection)
        conn.close()

    def test_connection_is_usable(self, tmp_path):
        db_path = tmp_path / "test.db"
        conn = db.create_connection(str(db_path))
        conn.execute("CREATE TABLE t (x INTEGER)")
        rows = conn.execute("SELECT * FROM t").fetchall()
        assert rows == []
        conn.close()


# ---------------------------------------------------------------------------
# table_exists
# ---------------------------------------------------------------------------

class TestTableExists:
    def test_existing_table_returns_true(self, tmp_path):
        db_path = tmp_path / "test.db"
        conn = db.create_connection(str(db_path))
        conn.execute("CREATE TABLE my_table (id INTEGER)")
        conn.commit()
        # Point the module-level conn to our test connection
        db.conn = conn
        assert db.table_exists("my_table") is True
        conn.close()

    def test_missing_table_returns_false(self, tmp_path):
        db_path = tmp_path / "test.db"
        conn = db.create_connection(str(db_path))
        db.conn = conn
        assert db.table_exists("nonexistent_table") is False
        conn.close()

    def test_after_table_dropped(self, tmp_path):
        db_path = tmp_path / "test.db"
        conn = db.create_connection(str(db_path))
        conn.execute("CREATE TABLE temp_tbl (x TEXT)")
        conn.commit()
        db.conn = conn
        assert db.table_exists("temp_tbl") is True
        conn.execute("DROP TABLE temp_tbl")
        conn.commit()
        assert db.table_exists("temp_tbl") is False
        conn.close()


# ---------------------------------------------------------------------------
# fetchone_query
# ---------------------------------------------------------------------------

class TestFetchoneQuery:
    def _setup(self, tmp_path):
        db_path = tmp_path / "test.db"
        conn = db.create_connection(str(db_path))
        conn.execute(
            "CREATE TABLE repository (repo_url TEXT PRIMARY KEY, stars_count TEXT)"
        )
        conn.execute(
            "INSERT INTO repository VALUES (?, ?)",
            ("https://github.com/foo/bar", "100"),
        )
        conn.commit()
        db.conn = conn
        return conn

    def test_existing_record_returns_true(self, tmp_path):
        conn = self._setup(tmp_path)
        result = db.fetchone_query("repository", "repo_url", "https://github.com/foo/bar")
        assert result is True
        conn.close()

    def test_missing_record_returns_false(self, tmp_path):
        conn = self._setup(tmp_path)
        result = db.fetchone_query("repository", "repo_url", "https://github.com/missing/repo")
        assert result is False
        conn.close()

    def test_empty_table_returns_false(self, tmp_path):
        db_path = tmp_path / "test.db"
        conn = db.create_connection(str(db_path))
        conn.execute("CREATE TABLE empty_tbl (repo_url TEXT)")
        conn.commit()
        db.conn = conn
        result = db.fetchone_query("empty_tbl", "repo_url", "https://anything.com")
        assert result is False
        conn.close()
