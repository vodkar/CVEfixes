"""
Commit extractor — traverses git repositories with PyDriller and writes
staging Parquet files for commits, file_change, and method_change.

Key differences from the original Code/collect_commits.py:
- code_before and code_after are both written to the blob store; only their
  SHA-256 hashes are stored in the file_change table
- method_change stores start_line/end_line only (no inline code column)
- Only before_change=True method rows are written
- Output goes to staging Parquet, not SQLite
"""



import logging
import re
import uuid
from pathlib import Path
from typing import Any

import polars as pl
import zstandard as zstd

logger = logging.getLogger("cvefixes.commit_extractor")

_ZSTD_DIFF_LEVEL = 3  # lighter compression for inline diff column

GIT_COMMIT_RE = re.compile(
    r"(((?P<repo>(https|http)://(bitbucket|github|gitlab)\.(org|com)/(?P<owner>[^/]+)/(?P<project>[^/]*))"
    r"/(commit|commits)/(?P<hash>\w+)#?)+)"
)


def _guess_language(code: str | None) -> str | None:
    """Detect programming language using guesslang (TF-backed)."""
    if not code:
        return None
    try:
        import os
        os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "3")
        from guesslang import Guess
        return Guess().language_name(code.strip())
    except Exception:
        return None


def _changed_methods_both(file: Any) -> tuple[set, set]:
    """Return (methods_in_new_version, methods_in_old_version) that were touched."""
    new_methods = file.methods or []
    old_methods = file.methods_before or []
    added = (file.diff_parsed or {}).get("added", [])
    deleted = (file.diff_parsed or {}).get("deleted", [])

    methods_new = {
        m for x in added for m in new_methods
        if m.start_line <= x[0] <= m.end_line
    }
    methods_old = {
        m for x in deleted for m in old_methods
        if m.start_line <= x[0] <= m.end_line
    }
    return methods_new, methods_old


def _compress_diff(diff: str | None) -> bytes | None:
    if not diff:
        return None
    cctx = zstd.ZstdCompressor(level=_ZSTD_DIFF_LEVEL)
    return cctx.compress(diff.encode("utf-8", errors="replace"))


def _get_method_rows(file: Any, file_change_id: int, blob_store: Any) -> list[dict]:
    """
    Extract method_change rows for *file*.

    Only before_change rows are stored (pre-fix state).
    No inline code is stored — start_line / end_line allow reconstruction via blob.
    """
    rows: list[dict] = []
    try:
        if not file.changed_methods:
            return rows
        _, methods_before = _changed_methods_both(file)
        if not methods_before or file.source_code_before is None:
            return rows
        for mb in methods_before:
            if mb.name == "(anonymous)" or not mb.name:
                continue
            rows.append({
                "method_change_id": uuid.uuid4().int & 0x7FFFFFFFFFFFFFFF,
                "file_change_id": file_change_id,
                "name": mb.name,
                "signature": mb.long_name,
                "start_line": mb.start_line,
                "end_line": mb.end_line,
                "before_change": True,
                "cyclomatic_complexity": mb.complexity,
                "nloc": mb.nloc,
                "token_count": mb.token_count,
            })
    except Exception as exc:
        logger.warning("Error extracting methods: %s", exc)
    return rows


def _get_file_rows(
    commit: Any,
    blob_store: Any,
) -> tuple[list[dict], list[dict]]:
    """Return (file_change_rows, method_change_rows) for one commit."""
    file_rows: list[dict] = []
    method_rows: list[dict] = []

    if not commit.modified_files:
        return file_rows, method_rows

    for file in commit.modified_files:
        try:
            prog_lang = _guess_language(file.source_code)
            file_change_id = uuid.uuid4().int & 0x7FFFFFFFFFFFFFFF

            # Store code_before and code_after in blob store; keep only hashes
            code_before_hash: str | None = None
            if file.source_code_before is not None:
                raw = file.source_code_before.encode("utf-8", errors="replace")
                code_before_hash = blob_store.write(raw)

            code_after_hash: str | None = None
            if file.source_code is not None:
                raw = file.source_code.encode("utf-8", errors="replace")
                code_after_hash = blob_store.write(raw)

            file_rows.append({
                "file_change_id": file_change_id,
                "hash": commit.hash,
                "filename": file.filename,
                "programming_language": prog_lang,
                "num_lines_added": file.added_lines,
                "num_lines_deleted": file.deleted_lines,
                "code_before_hash": code_before_hash,
                "code_after_hash": code_after_hash,
                "diff": _compress_diff(file.diff),
                "nloc": file.nloc,
                "complexity": file.complexity,
            })

            meths = _get_method_rows(file, file_change_id, blob_store)
            method_rows.extend(meths)
        except Exception as exc:
            logger.warning("Error processing file %s in %s: %s", file.filename, commit.hash, exc)

    return file_rows, method_rows


def extract_commits(
    repo_url: str,
    hashes: list[str],
    blob_store: Any,
    num_workers: int = 4,
) -> tuple[list[dict], list[dict], list[dict]]:
    """
    Traverse *repo_url* for the given *hashes* and return
    (commit_rows, file_rows, method_rows).
    """
    from pydriller import Repository

    if "github" in repo_url and not repo_url.endswith(".git"):
        repo_url = repo_url + ".git"

    commit_rows: list[dict] = []
    file_rows: list[dict] = []
    method_rows: list[dict] = []

    single_hash = hashes[0] if len(hashes) == 1 else None
    only_commits = None if single_hash else hashes

    try:
        for commit in Repository(
            path_to_repo=repo_url,
            only_commits=only_commits,
            single=single_hash,
            num_workers=num_workers,
        ).traverse_commits():
            try:
                commit_rows.append({
                    "hash": commit.hash,
                    "repo_url": repo_url.removesuffix(".git"),
                    "author": commit.author.name if commit.author else None,
                    "commit_date": commit.committer_date,
                    "dmm_unit_size": commit.dmm_unit_size,
                    "dmm_unit_complexity": commit.dmm_unit_complexity,
                    "num_lines_added": commit.insertions,
                    "num_lines_deleted": commit.deletions,
                })
                fr, mr = _get_file_rows(commit, blob_store)
                file_rows.extend(fr)
                method_rows.extend(mr)
            except Exception as exc:
                logger.warning("Error processing commit %s: %s", commit.hash, exc)
    except Exception as exc:
        logger.warning("Error traversing repo %s: %s", repo_url, exc)

    return commit_rows, file_rows, method_rows


def run_collection(
    df_fixes: pl.DataFrame,
    blob_store: Any,
    staging_path: str | Path,
    num_workers: int = 4,
    already_done_hashes: set[str] | None = None,
) -> None:
    """
    For each unique repo in *df_fixes*, extract commits and write staging Parquets.

    Parameters
    ----------
    df_fixes:            DataFrame with columns cve_id, hash, repo_url
    blob_store:          BlobStore instance
    staging_path:        directory to write staging Parquet files
    num_workers:         PyDriller parallelism
    already_done_hashes: hashes already present in staging (incremental update)
    """
    staging_path = Path(staging_path)
    staging_path.mkdir(parents=True, exist_ok=True)

    if already_done_hashes:
        df_fixes = df_fixes.filter(~pl.col("hash").is_in(list(already_done_hashes)))

    repo_urls = df_fixes["repo_url"].unique().to_list()
    all_commits: list[dict] = []
    all_files: list[dict] = []
    all_methods: list[dict] = []

    for idx, repo_url in enumerate(repo_urls, 1):
        hashes = (
            df_fixes
            .filter(pl.col("repo_url") == repo_url)["hash"]
            .unique()
            .to_list()
        )
        logger.info(
            "Processing repo %d/%d: %s (%d hashes)",
            idx, len(repo_urls), repo_url.split("/")[-1], len(hashes),
        )
        try:
            cr, fr, mr = extract_commits(repo_url, hashes, blob_store, num_workers)
            all_commits.extend(cr)
            all_files.extend(fr)
            all_methods.extend(mr)
        except Exception as exc:
            logger.warning("Skipping repo %s: %s", repo_url, exc)

    def _write(rows: list[dict], name: str) -> None:
        if not rows:
            logger.info("No rows for %s — skipping write", name)
            return
        out = staging_path / f"{name}_staging.parquet"
        # Append to existing staging if present
        df_new = pl.DataFrame(rows)
        if out.exists():
            df_existing = pl.read_parquet(out)
            df_new = pl.concat([df_existing, df_new])
        df_new.write_parquet(out, compression="zstd")
        logger.info("Wrote %d rows to %s", len(df_new), out)

    _write(all_commits, "commits")
    _write(all_files, "file_change")
    _write(all_methods, "method_change")
