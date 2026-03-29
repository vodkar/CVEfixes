"""
Content-addressable blob storage for CVEfixes.

Layout on disk:
    blobs/{sha256[:2]}/{sha256[2:]}.zst

Key properties:
- Write-once: once a blob is written it is never modified
- Deduplicated: existence is checked via filesystem before writing
- Compressed: zstandard level 19 on write, transparent on read
"""



import hashlib
from pathlib import Path

import zstandard as zstd


_ZSTD_LEVEL = 19
_ZSTD_READ_THREADS = 0  # 0 = single-threaded (safe for random access)


class BlobStore:
    """Content-addressable store backed by the local filesystem."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._compressor = zstd.ZstdCompressor(level=_ZSTD_LEVEL)
        self._decompressor = zstd.ZstdDecompressor()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def write(self, content: bytes) -> str:
        """
        Write *content* to the store, returning its SHA-256 hex digest.

        If a blob with the same digest already exists the write is skipped
        (dedup happens structurally — no post-processing needed).
        """
        digest = self._sha256(content)
        path = self._path(digest)
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            compressed = self._compressor.compress(content)
            # Atomic write: write to temp file then rename
            tmp = path.with_suffix(".tmp")
            tmp.write_bytes(compressed)
            tmp.rename(path)
        return digest

    def read(self, sha256_hash: str) -> bytes:
        """Decompress and return the blob identified by *sha256_hash*."""
        path = self._path(sha256_hash)
        if not path.exists():
            raise FileNotFoundError(f"Blob not found: {sha256_hash}")
        compressed = path.read_bytes()
        return self._decompressor.decompress(compressed)

    def exists(self, sha256_hash: str) -> bool:
        """Return True if a blob with *sha256_hash* is present in the store."""
        return self._path(sha256_hash).exists()

    def read_lines(self, sha256_hash: str, start_line: int, end_line: int) -> str:
        """
        Return lines [start_line, end_line] (1-based, inclusive) from the blob.

        The full blob is decompressed into memory before slicing; this is a
        convenience wrapper around read() rather than a streaming reader.
        """
        content = self.read(sha256_hash)
        lines = content.decode("utf-8", errors="replace").splitlines()
        # Convert 1-based inclusive to 0-based slice
        return "\n".join(lines[start_line - 1 : end_line])

    def stats(self) -> dict:
        """Return basic statistics about the store."""
        blobs = list(self.root.rglob("*.zst"))
        total_compressed = sum(p.stat().st_size for p in blobs)
        return {
            "blob_count": len(blobs),
            "total_compressed_bytes": total_compressed,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _path(self, sha256_hash: str) -> Path:
        """Map a SHA-256 digest to its on-disk path."""
        prefix = sha256_hash[:2]
        suffix = sha256_hash[2:]
        return self.root / prefix / f"{suffix}.zst"

    @staticmethod
    def _sha256(content: bytes) -> str:
        return hashlib.sha256(content).hexdigest()
