"""
Tests for Code/collect_commits.py

Covers:
- clean_string: whitespace + space removal
- get_method_code: line-based source slicing
- extract_project_links: regex extraction of commit URLs from CVE references
- changed_methods_both: method change detection via diff line ranges
"""

import ast
import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pandas as pd
import pytest

from collect_commits import (
    clean_string,
    get_method_code,
    extract_project_links,
    changed_methods_both,
)


# ---------------------------------------------------------------------------
# clean_string
# ---------------------------------------------------------------------------

class TestCleanString:
    def test_strips_leading_trailing(self):
        assert clean_string("  foo  ") == "foo"

    def test_removes_internal_spaces(self):
        assert clean_string("int foo ( int x )") == "intfoo(intx)"

    def test_empty_string(self):
        assert clean_string("") == ""

    def test_no_spaces_unchanged(self):
        assert clean_string("foo") == "foo"


# ---------------------------------------------------------------------------
# get_method_code
# ---------------------------------------------------------------------------

class TestGetMethodCode:
    _source = "line1\nline2\nline3\nline4\nline5"

    def test_full_range(self):
        assert get_method_code(self._source, 1, 5) == self._source

    def test_inner_slice(self):
        assert get_method_code(self._source, 2, 4) == "line2\nline3\nline4"

    def test_single_line(self):
        assert get_method_code(self._source, 3, 3) == "line3"

    def test_none_source_returns_none(self):
        assert get_method_code(None, 1, 3) is None

    def test_start_equals_end_first_line(self):
        assert get_method_code(self._source, 1, 1) == "line1"

    def test_out_of_bounds_returns_available(self):
        # Requesting lines beyond the file just returns what's there
        result = get_method_code(self._source, 4, 10)
        assert result == "line4\nline5"

    def test_string_line_numbers_converted(self):
        # Original code casts to int, so strings should work too
        assert get_method_code(self._source, "2", "3") == "line2\nline3"


# ---------------------------------------------------------------------------
# extract_project_links
# ---------------------------------------------------------------------------

def _make_cve_df(cve_refs):
    """Build a minimal CVE master DataFrame from {cve_id: [url, ...]} mapping."""
    rows = []
    for cve_id, urls in cve_refs.items():
        ref_list = [{"url": u, "name": "", "refsource": "CONFIRM", "tags": []} for u in urls]
        rows.append({"cve_id": cve_id, "reference_json": str(ref_list)})
    return pd.DataFrame(rows)


_PANDAS_APPEND_XFAIL = pytest.mark.xfail(
    strict=False,
    reason="extract_project_links() uses DataFrame.append() which was removed "
           "in pandas 2.0. Original code requires pandas ~1.2.",
)


@_PANDAS_APPEND_XFAIL
class TestExtractProjectLinks:
    def test_github_commit_url(self):
        df = _make_cve_df({
            "CVE-2021-0001": ["https://github.com/foo/bar/commit/abc1234567890abcdef"]
        })
        result = extract_project_links(df)
        assert len(result) == 1
        assert result.iloc[0]["cve_id"] == "CVE-2021-0001"
        assert result.iloc[0]["hash"] == "abc1234567890abcdef"
        assert result.iloc[0]["repo_url"] == "https://github.com/foo/bar"

    def test_gitlab_commit_url(self):
        df = _make_cve_df({
            "CVE-2021-0002": ["https://gitlab.com/org/project/commit/deadbeef"]
        })
        result = extract_project_links(df)
        assert len(result) == 1
        assert result.iloc[0]["repo_url"] == "https://gitlab.com/org/project"

    def test_bitbucket_commit_url(self):
        df = _make_cve_df({
            "CVE-2021-0003": ["https://bitbucket.org/user/repo/commits/cafebabe"]
        })
        result = extract_project_links(df)
        assert len(result) == 1
        assert result.iloc[0]["repo_url"] == "https://bitbucket.org/user/repo"

    def test_http_converted_to_https(self):
        df = _make_cve_df({
            "CVE-2021-0004": ["http://github.com/foo/bar/commit/abc123"]
        })
        result = extract_project_links(df)
        assert result.iloc[0]["repo_url"].startswith("https://")

    def test_non_commit_url_ignored(self):
        df = _make_cve_df({
            "CVE-2021-0005": [
                "https://nvd.nist.gov/vuln/detail/CVE-2021-0005",
                "https://example.com/advisory/42",
            ]
        })
        result = extract_project_links(df)
        assert len(result) == 0

    def test_multiple_commits_same_cve(self):
        df = _make_cve_df({
            "CVE-2021-0006": [
                "https://github.com/foo/bar/commit/aaa111",
                "https://github.com/foo/bar/commit/bbb222",
            ]
        })
        result = extract_project_links(df)
        assert len(result) == 2
        hashes = set(result["hash"].values)
        assert hashes == {"aaa111", "bbb222"}

    def test_duplicate_links_deduplicated(self):
        df = _make_cve_df({
            "CVE-2021-0007": [
                "https://github.com/foo/bar/commit/abc123",
                "https://github.com/foo/bar/commit/abc123",  # duplicate
            ]
        })
        result = extract_project_links(df)
        assert len(result) == 1

    def test_empty_references(self):
        df = pd.DataFrame([
            {"cve_id": "CVE-2021-0008", "reference_json": "[]"}
        ])
        result = extract_project_links(df)
        assert len(result) == 0

    def test_multiple_cves(self):
        df = _make_cve_df({
            "CVE-2021-0001": ["https://github.com/a/b/commit/hash1"],
            "CVE-2021-0002": ["https://github.com/c/d/commit/hash2"],
        })
        result = extract_project_links(df)
        assert len(result) == 2
        assert set(result["cve_id"].values) == {"CVE-2021-0001", "CVE-2021-0002"}

    def test_returns_dataframe_with_correct_columns(self):
        df = _make_cve_df({
            "CVE-2021-0001": ["https://github.com/a/b/commit/abc"]
        })
        result = extract_project_links(df)
        assert set(result.columns) >= {"cve_id", "hash", "repo_url"}


# ---------------------------------------------------------------------------
# changed_methods_both
# ---------------------------------------------------------------------------

def _make_method(name, start, end):
    m = MagicMock()
    m.name = name
    m.start_line = start
    m.end_line = end
    m.long_name = name
    return m


def _make_file(methods_after, methods_before, added_lines, deleted_lines):
    f = MagicMock()
    f.methods = methods_after
    f.methods_before = methods_before
    f.diff_parsed = {"added": added_lines, "deleted": deleted_lines}
    return f


class TestChangedMethodsBoth:
    def test_method_containing_added_line_detected(self):
        m = _make_method("foo", start=10, end=20)
        f = _make_file(
            methods_after=[m],
            methods_before=[],
            added_lines=[(15, "new code")],
            deleted_lines=[],
        )
        new, old = changed_methods_both(f)
        assert m in new
        assert len(old) == 0

    def test_method_containing_deleted_line_detected(self):
        mb = _make_method("bar", start=5, end=15)
        f = _make_file(
            methods_after=[],
            methods_before=[mb],
            added_lines=[],
            deleted_lines=[(10, "old code")],
        )
        new, old = changed_methods_both(f)
        assert mb in old
        assert len(new) == 0

    def test_method_outside_diff_not_included(self):
        m = _make_method("unrelated", start=100, end=200)
        f = _make_file(
            methods_after=[m],
            methods_before=[],
            added_lines=[(50, "something")],
            deleted_lines=[],
        )
        new, _ = changed_methods_both(f)
        assert m not in new

    def test_both_before_and_after_detected(self):
        m_new = _make_method("func_new", start=10, end=30)
        m_old = _make_method("func_old", start=10, end=30)
        f = _make_file(
            methods_after=[m_new],
            methods_before=[m_old],
            added_lines=[(15, "+line")],
            deleted_lines=[(20, "-line")],
        )
        new, old = changed_methods_both(f)
        assert m_new in new
        assert m_old in old

    def test_empty_diff_no_changes(self):
        m = _make_method("untouched", start=1, end=50)
        f = _make_file(
            methods_after=[m],
            methods_before=[m],
            added_lines=[],
            deleted_lines=[],
        )
        new, old = changed_methods_both(f)
        assert len(new) == 0
        assert len(old) == 0

    def test_multiple_methods_only_touched_returned(self):
        m1 = _make_method("touched", start=10, end=20)
        m2 = _make_method("untouched", start=50, end=80)
        f = _make_file(
            methods_after=[m1, m2],
            methods_before=[],
            added_lines=[(15, "change")],
            deleted_lines=[],
        )
        new, _ = changed_methods_both(f)
        assert m1 in new
        assert m2 not in new

    def test_boundary_line_included(self):
        # A change exactly on start_line or end_line should match
        m = _make_method("boundary_func", start=10, end=20)
        f_start = _make_file([m], [], [(10, "start")], [])
        f_end = _make_file([m], [], [(20, "end")], [])
        new_start, _ = changed_methods_both(f_start)
        new_end, _ = changed_methods_both(f_end)
        assert m in new_start
        assert m in new_end
