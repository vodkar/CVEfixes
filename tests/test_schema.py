"""
Unit tests for storage/schema.py

Tests:
- Pydantic model validation (valid and invalid inputs)
- Arrow schema existence and field types
"""

import datetime

import pyarrow as pa
import pytest

from storage.schema import (
    CveRecord,
    CweRecord,
    CweClassification,
    RepositoryRecord,
    CommitRecord,
    FixRecord,
    FileChangeRecord,
    MethodChangeRecord,
    TABLE_SCHEMAS,
    CVE_SCHEMA,
    FILE_CHANGE_SCHEMA,
    METHOD_CHANGE_SCHEMA,
)


# ---------------------------------------------------------------------------
# Pydantic model tests
# ---------------------------------------------------------------------------

class TestCveRecord:
    def test_valid(self):
        r = CveRecord(cve_id="CVE-2021-1234", severity_v3=7.5)
        assert r.cve_id == "CVE-2021-1234"
        assert r.severity_v3 == pytest.approx(7.5)

    def test_strips_whitespace(self):
        r = CveRecord(cve_id="  CVE-2021-1234  ")
        assert r.cve_id == "CVE-2021-1234"

    def test_empty_cve_id_raises(self):
        with pytest.raises(Exception):
            CveRecord(cve_id="   ")

    def test_optional_fields_default_none(self):
        r = CveRecord(cve_id="CVE-2021-1")
        assert r.published_date is None
        assert r.description is None


class TestCommitRecord:
    def test_valid(self):
        r = CommitRecord(hash="abc123", repo_id=1)
        assert r.hash == "abc123"

    def test_empty_hash_raises(self):
        with pytest.raises(Exception):
            CommitRecord(hash="", repo_id=1)

    def test_strips_hash(self):
        r = CommitRecord(hash="  deadbeef  ", repo_id=1)
        assert r.hash == "deadbeef"


class TestFileChangeRecord:
    def test_valid(self):
        r = FileChangeRecord(file_change_id=1, hash="abc")
        assert r.file_change_id == 1

    def test_code_before_hash_optional(self):
        r = FileChangeRecord(file_change_id=1, hash="abc")
        assert r.code_before_hash is None

    def test_code_after_hash_optional(self):
        r = FileChangeRecord(file_change_id=1, hash="abc")
        assert r.code_after_hash is None

    def test_both_hashes_can_be_set(self):
        before = "a" * 64
        after = "b" * 64
        r = FileChangeRecord(
            file_change_id=1, hash="abc",
            code_before_hash=before, code_after_hash=after,
        )
        assert r.code_before_hash == before
        assert r.code_after_hash == after


class TestMethodChangeRecord:
    def test_before_change_default_false(self):
        r = MethodChangeRecord(method_change_id=1, file_change_id=2)
        assert r.before_change is False

    def test_valid_with_all_fields(self):
        r = MethodChangeRecord(
            method_change_id=42,
            file_change_id=7,
            name="my_func",
            signature="int my_func(void)",
            start_line=10,
            end_line=25,
            before_change=True,
            cyclomatic_complexity=3,
            nloc=15,
            token_count=50,
        )
        assert r.name == "my_func"
        assert r.before_change is True


# ---------------------------------------------------------------------------
# Arrow schema tests
# ---------------------------------------------------------------------------

class TestArrowSchemas:
    def test_all_schemas_present(self):
        expected = {
            "cve", "cwe", "cwe_classification", "repository",
            "commits", "fixes", "file_change", "method_change",
        }
        assert set(TABLE_SCHEMAS.keys()) == expected

    def test_cve_schema_fields(self):
        names = {f.name for f in CVE_SCHEMA}
        assert "cve_id" in names
        assert "published_date" in names
        assert "severity_v2" in names
        assert "severity_v3" in names

    def test_file_change_has_blob_refs(self):
        names = {f.name for f in FILE_CHANGE_SCHEMA}
        assert "code_before_hash" in names
        assert "code_after_hash" in names
        # No inline source code columns — only blob-store references
        assert "code_before" not in names
        assert "code_after" not in names

    def test_file_change_blob_refs_are_strings(self):
        fields = {f.name: f for f in FILE_CHANGE_SCHEMA}
        assert pa.types.is_string(fields["code_before_hash"].type)
        assert pa.types.is_string(fields["code_after_hash"].type)

    def test_method_change_has_code_column(self):
        names = {f.name for f in METHOD_CHANGE_SCHEMA}
        assert "code" in names
        assert "start_line" in names
        assert "end_line" in names

    def test_method_change_code_is_large_utf8(self):
        field = next(f for f in METHOD_CHANGE_SCHEMA if f.name == "code")
        assert pa.types.is_large_unicode(field.type)

    def test_file_change_diff_is_large_binary(self):
        field = next(f for f in FILE_CHANGE_SCHEMA if f.name == "diff")
        assert pa.types.is_large_binary(field.type)

    def test_cve_id_is_dict_encoded(self):
        field = next(f for f in CVE_SCHEMA if f.name == "cve_id")
        assert pa.types.is_dictionary(field.type)
