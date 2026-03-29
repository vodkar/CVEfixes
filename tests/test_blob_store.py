"""
Unit tests for storage/blob_store.py

Tests:
- write/read round-trip
- deduplication (second write returns same hash, skips IO)
- exists() correctness
- read_lines() slicing
- stats() accuracy
"""

import os
import tempfile

import pytest

from storage.blob_store import BlobStore


@pytest.fixture
def store(tmp_path):
    return BlobStore(root=tmp_path / "blobs")


def test_write_returns_hex_digest(store):
    digest = store.write(b"hello world")
    assert len(digest) == 64  # SHA-256 hex = 64 chars
    assert all(c in "0123456789abcdef" for c in digest)


def test_round_trip(store):
    content = b"the quick brown fox jumps over the lazy dog"
    digest = store.write(content)
    assert store.read(digest) == content


def test_dedup_returns_same_hash(store):
    content = b"duplicate content"
    h1 = store.write(content)
    h2 = store.write(content)
    assert h1 == h2


def test_dedup_does_not_double_write(store, tmp_path):
    content = b"deduplicated"
    h = store.write(content)
    path = store._path(h)
    mtime_before = path.stat().st_mtime

    # Second write — file should not be touched
    store.write(content)
    assert path.stat().st_mtime == mtime_before


def test_different_content_different_hash(store):
    h1 = store.write(b"content A")
    h2 = store.write(b"content B")
    assert h1 != h2


def test_exists_true(store):
    content = b"existence check"
    digest = store.write(content)
    assert store.exists(digest) is True


def test_exists_false(store):
    assert store.exists("a" * 64) is False


def test_read_missing_raises(store):
    with pytest.raises(FileNotFoundError):
        store.read("0" * 64)


def test_read_lines(store):
    source = "line1\nline2\nline3\nline4\nline5"
    digest = store.write(source.encode())
    result = store.read_lines(digest, start_line=2, end_line=4)
    assert result == "line2\nline3\nline4"


def test_read_lines_single(store):
    source = "alpha\nbeta\ngamma"
    digest = store.write(source.encode())
    assert store.read_lines(digest, 1, 1) == "alpha"
    assert store.read_lines(digest, 3, 3) == "gamma"


def test_stats_empty(store):
    stats = store.stats()
    assert stats["blob_count"] == 0
    assert stats["total_compressed_bytes"] == 0


def test_stats_after_writes(store):
    store.write(b"blob A")
    store.write(b"blob B")
    store.write(b"blob A")  # dedup — no extra file
    stats = store.stats()
    assert stats["blob_count"] == 2
    assert stats["total_compressed_bytes"] > 0


def test_compression_reduces_size(store):
    # Highly compressible content
    content = (b"AAAA" * 1000)
    digest = store.write(content)
    compressed_size = store._path(digest).stat().st_size
    assert compressed_size < len(content)


def test_path_structure(store):
    content = b"path structure test"
    digest = store.write(content)
    expected = store.root / digest[:2] / f"{digest[2:]}.zst"
    assert store._path(digest) == expected
    assert expected.exists()
