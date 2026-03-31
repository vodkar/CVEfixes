"""
Shared fixtures for tests of the legacy Code/ implementation.

Bootstrap order:
  1. pytest_configure hook creates a temp .CVEfixes.ini and writes its
     directory to an env var — this runs before any test module is imported.
  2. The sys.path additions expose Code/ so that `import configuration`
     resolves.
  3. Individual tests import directly; the ini file is already on disk.
"""

import os
import sqlite3
import sys
import tempfile
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# sys.path bootstrap (runs at conftest import time, before collection)
# ---------------------------------------------------------------------------
ROOT = Path(__file__).parent.parent.parent
CODE = ROOT / "Code"
for p in (str(ROOT), str(CODE)):
    if p not in sys.path:
        sys.path.insert(0, p)

# ---------------------------------------------------------------------------
# Stub heavy optional dependencies that aren't installed in the test env
# ---------------------------------------------------------------------------
from types import ModuleType
from unittest.mock import MagicMock

def _stub_module(name: str) -> None:
    """Insert a MagicMock module into sys.modules so imports don't fail."""
    if name not in sys.modules:
        mod = MagicMock(spec=ModuleType(name))
        mod.__name__ = name
        sys.modules[name] = mod

# guesslang pulls in TensorFlow — stub the whole tree
for _mod in ("guesslang", "tensorflow", "tf"):
    _stub_module(_mod)

# pydriller is only needed for actual git cloning, not for the pure functions we test
_stub_module("pydriller")
sys.modules["pydriller"].Repository = MagicMock()

# Provide a real-enough Guess class so collect_commits.guess_pl() works
_gl_mod = sys.modules["guesslang"]
_gl_mod.Guess = MagicMock(return_value=MagicMock(language_name=MagicMock(return_value="C")))

# ---------------------------------------------------------------------------
# pytest_configure — runs before any test module is imported
# ---------------------------------------------------------------------------

_TMP_CFG_DIR: Path | None = None


def pytest_configure(config):
    """Create a temp config dir + .CVEfixes.ini before collection starts."""
    global _TMP_CFG_DIR
    _TMP_CFG_DIR = Path(tempfile.mkdtemp(prefix="cvefixes_test_"))
    ini = _TMP_CFG_DIR / ".CVEfixes.ini"
    ini.write_text(
        "[CVEfixes]\n"
        f"database_path = {_TMP_CFG_DIR}\n"
        "database_name = test_cvefixes.db\n"
        "sample_limit = 0\n"
        "num_workers = 1\n"
        "logging_level = WARNING\n"
        "[GitHub]\n"
        "user = None\n"
        "token = None\n"
    )
    # Change working directory so configuration.py's ConfigParser.read() finds
    # the ini when it searches for '.CVEfixes.ini' in the current directory.
    os.chdir(_TMP_CFG_DIR)


def pytest_unconfigure(config):
    """Restore working dir after test session."""
    os.chdir(ROOT)


# ---------------------------------------------------------------------------
# In-memory SQLite helpers
# ---------------------------------------------------------------------------

def make_db_with_tables():
    """
    Return an in-memory sqlite3 connection pre-populated with the full
    CVEfixes schema (string columns — matches the original applymap(str)).
    """
    conn = sqlite3.connect(":memory:")
    _create_schema(conn)
    return conn


def _create_schema(conn):
    stmts = [
        """CREATE TABLE IF NOT EXISTS cve (
            cve_id TEXT PRIMARY KEY,
            published_date TEXT,
            description TEXT,
            reference_json TEXT,
            problemtype_json TEXT
        )""",
        """CREATE TABLE IF NOT EXISTS fixes (
            cve_id TEXT,
            hash TEXT,
            repo_url TEXT,
            PRIMARY KEY (cve_id, hash, repo_url)
        )""",
        """CREATE TABLE IF NOT EXISTS commits (
            hash TEXT PRIMARY KEY,
            repo_url TEXT,
            author TEXT,
            commit_date TEXT,
            num_lines_added TEXT,
            num_lines_deleted TEXT,
            dmm_unit_size TEXT,
            dmm_unit_complexity TEXT
        )""",
        """CREATE TABLE IF NOT EXISTS repository (
            repo_url TEXT PRIMARY KEY,
            repo_name TEXT,
            description TEXT,
            date_created TEXT,
            owner TEXT,
            stars_count TEXT,
            forks_count TEXT
        )""",
        """CREATE TABLE IF NOT EXISTS file_change (
            file_change_id TEXT PRIMARY KEY,
            hash TEXT,
            filename TEXT,
            programming_language TEXT,
            num_lines_added TEXT,
            num_lines_deleted TEXT,
            code_before TEXT,
            code_after TEXT,
            diff TEXT,
            nloc TEXT,
            complexity TEXT,
            token_count TEXT
        )""",
        """CREATE TABLE IF NOT EXISTS method_change (
            method_change_id TEXT PRIMARY KEY,
            file_change_id TEXT,
            name TEXT,
            signature TEXT,
            start_line TEXT,
            end_line TEXT,
            code TEXT,
            nloc TEXT,
            complexity TEXT,
            token_count TEXT,
            before_change TEXT
        )""",
        """CREATE TABLE IF NOT EXISTS cwe (
            cwe_id TEXT PRIMARY KEY,
            cwe_name TEXT,
            description TEXT
        )""",
        """CREATE TABLE IF NOT EXISTS cwe_classification (
            cve_id TEXT,
            cwe_id TEXT,
            PRIMARY KEY (cve_id, cwe_id)
        )""",
    ]
    for stmt in stmts:
        conn.execute(stmt)
    conn.commit()


def make_file_db(path: Path) -> sqlite3.Connection:
    """Create the schema in a file-backed SQLite database."""
    conn = sqlite3.connect(str(path))
    _create_schema(conn)
    return conn


@pytest.fixture
def db_conn():
    """Yield a fresh in-memory database connection per test."""
    conn = make_db_with_tables()
    yield conn
    conn.close()
