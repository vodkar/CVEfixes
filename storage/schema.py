"""
Pydantic validation models and PyArrow schemas for CVEfixes Parquet storage.

Pydantic models validate data at collection time.
Arrow schemas define the on-disk column types written to Parquet.
"""

from __future__ import annotations

import datetime
from typing import Optional

import pyarrow as pa
from pydantic import BaseModel, field_validator


# ---------------------------------------------------------------------------
# Pydantic validation models
# ---------------------------------------------------------------------------

class CveRecord(BaseModel):
    cve_id: str
    published_date: Optional[datetime.date] = None
    severity_v2: Optional[float] = None
    severity_v3: Optional[float] = None
    description: Optional[str] = None

    @field_validator("cve_id")
    @classmethod
    def cve_id_nonempty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("cve_id must not be empty")
        return v.strip()


class CweRecord(BaseModel):
    cwe_id: str
    cwe_name: Optional[str] = None
    description: Optional[str] = None
    extended_description: Optional[str] = None
    url: Optional[str] = None
    is_category: bool = False


class CweClassification(BaseModel):
    cve_id: str
    cwe_id: str


class RepositoryRecord(BaseModel):
    repo_id: int
    url: str
    primary_language: Optional[str] = None
    stars: Optional[int] = None
    created_at: Optional[datetime.date] = None


class CommitRecord(BaseModel):
    hash: str
    repo_id: int
    commit_date: Optional[datetime.datetime] = None
    author: Optional[str] = None
    dmm_unit_size: Optional[float] = None
    dmm_unit_complexity: Optional[float] = None
    num_lines_added: Optional[int] = None
    num_lines_deleted: Optional[int] = None

    @field_validator("hash")
    @classmethod
    def hash_nonempty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("hash must not be empty")
        return v.strip()


class FixRecord(BaseModel):
    cve_id: str
    hash: str


class FileChangeRecord(BaseModel):
    file_change_id: int
    hash: str
    filename: Optional[str] = None
    programming_language: Optional[str] = None
    num_lines_added: Optional[int] = None
    num_lines_deleted: Optional[int] = None
    code_before_hash: Optional[str] = None   # SHA-256 reference into blob store
    diff: Optional[bytes] = None             # stored inline, zstd-compressed
    nloc: Optional[int] = None
    complexity: Optional[int] = None


class MethodChangeRecord(BaseModel):
    method_change_id: int
    file_change_id: int
    name: Optional[str] = None
    signature: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    before_change: bool = False
    cyclomatic_complexity: Optional[int] = None
    nloc: Optional[int] = None
    token_count: Optional[int] = None


# ---------------------------------------------------------------------------
# PyArrow schemas (match Pydantic models — used by Parquet writers)
# ---------------------------------------------------------------------------

CVE_SCHEMA = pa.schema([
    pa.field("cve_id",        pa.dictionary(pa.int32(), pa.string()), nullable=False),
    pa.field("published_date", pa.date32()),
    pa.field("severity_v2",   pa.float32()),
    pa.field("severity_v3",   pa.float32()),
    pa.field("description",   pa.string()),
])

CWE_SCHEMA = pa.schema([
    pa.field("cwe_id",               pa.dictionary(pa.int32(), pa.string()), nullable=False),
    pa.field("cwe_name",             pa.string()),
    pa.field("description",          pa.string()),
    pa.field("extended_description", pa.string()),
    pa.field("url",                  pa.string()),
    pa.field("is_category",          pa.bool_()),
])

CWE_CLASSIFICATION_SCHEMA = pa.schema([
    pa.field("cve_id", pa.dictionary(pa.int32(), pa.string()), nullable=False),
    pa.field("cwe_id", pa.dictionary(pa.int32(), pa.string()), nullable=False),
])

REPOSITORY_SCHEMA = pa.schema([
    pa.field("repo_id",          pa.int32(), nullable=False),
    pa.field("url",              pa.string()),
    pa.field("primary_language", pa.dictionary(pa.int32(), pa.string())),
    pa.field("stars",            pa.int32()),
    pa.field("created_at",       pa.date32()),
])

COMMITS_SCHEMA = pa.schema([
    pa.field("hash",                pa.string(), nullable=False),
    pa.field("repo_id",             pa.int32()),
    pa.field("commit_date",         pa.timestamp("us", tz="UTC")),
    pa.field("author",              pa.dictionary(pa.int32(), pa.string())),
    pa.field("dmm_unit_size",       pa.float32()),
    pa.field("dmm_unit_complexity", pa.float32()),
    pa.field("num_lines_added",     pa.int32()),
    pa.field("num_lines_deleted",   pa.int32()),
])

FIXES_SCHEMA = pa.schema([
    pa.field("cve_id", pa.dictionary(pa.int32(), pa.string()), nullable=False),
    pa.field("hash",   pa.string(), nullable=False),
])

FILE_CHANGE_SCHEMA = pa.schema([
    pa.field("file_change_id",      pa.int64(), nullable=False),
    pa.field("hash",                pa.string()),
    pa.field("filename",            pa.string()),
    pa.field("programming_language", pa.dictionary(pa.int32(), pa.string())),
    pa.field("num_lines_added",     pa.int32()),
    pa.field("num_lines_deleted",   pa.int32()),
    pa.field("code_before_hash",    pa.string()),   # blob store reference
    pa.field("diff",                pa.large_binary()),  # inline zstd diff
    pa.field("nloc",                pa.int32()),
    pa.field("complexity",          pa.int32()),
])

METHOD_CHANGE_SCHEMA = pa.schema([
    pa.field("method_change_id",      pa.int64(), nullable=False),
    pa.field("file_change_id",        pa.int64()),
    pa.field("name",                  pa.string()),
    pa.field("signature",             pa.string()),
    pa.field("start_line",            pa.int32()),
    pa.field("end_line",              pa.int32()),
    pa.field("before_change",         pa.bool_()),
    pa.field("cyclomatic_complexity", pa.int32()),
    pa.field("nloc",                  pa.int32()),
    pa.field("token_count",           pa.int32()),
])

# Map table name → Arrow schema (used by writer and catalog)
TABLE_SCHEMAS: dict[str, pa.Schema] = {
    "cve":                CVE_SCHEMA,
    "cwe":                CWE_SCHEMA,
    "cwe_classification": CWE_CLASSIFICATION_SCHEMA,
    "repository":         REPOSITORY_SCHEMA,
    "commits":            COMMITS_SCHEMA,
    "fixes":              FIXES_SCHEMA,
    "file_change":        FILE_CHANGE_SCHEMA,
    "method_change":      METHOD_CHANGE_SCHEMA,
}
