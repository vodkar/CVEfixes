#!/usr/bin/env python3
"""
CVEfixes collection entry point — Parquet/DuckDB backend.

Usage:
    # Full collection (auto-resumes after failure via checkpoint file)
    python collect.py

    # Sample collection (fast, current year only, 25 CVEs)
    python collect.py --sample

    # Weekly incremental update (new CVEs only)
    python collect.py --update

    # Force a clean restart — discards checkpoint and staging files
    python collect.py --reset

    # Just rebuild the DuckDB catalog (e.g. after manual Parquet edits)
    python collect.py --catalog-only
"""



import argparse
import logging
import shutil
import sys
from configparser import ConfigParser
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_CONFIG_PATHS = [
    ".CVEfixes.ini",
    Path.home() / ".config" / "CVEfixes.ini",
    Path.home() / ".CVEfixes.ini",
]


def load_config() -> dict:
    """Load settings from .CVEfixes.ini (same format as the original)."""
    cfg = ConfigParser()
    if not cfg.read(DEFAULT_CONFIG_PATHS):
        logging.warning(
            "Cannot find CVEfixes config file; using defaults. "
            "See INSTALL.md for setup instructions."
        )
        return {}

    return {
        "data_path":      cfg.get("CVEfixes", "database_path", fallback="Data"),
        "parquet_base":   cfg.get("CVEfixes", "parquet_path",  fallback="parquet"),
        "duckdb_path":    cfg.get("CVEfixes", "duckdb_path",   fallback="cvefixes.duckdb"),
        "sample_limit":   cfg.getint("CVEfixes", "sample_limit", fallback=0),
        "num_workers":    cfg.getint("CVEfixes", "num_workers", fallback=4),
        "logging_level":  cfg.get("CVEfixes", "logging_level", fallback="INFO"),
        "github_user":    cfg.get("GitHub", "user",  fallback=None),
        "github_token":   cfg.get("GitHub", "token", fallback=None),
        "nvd_api_key":    cfg.get("NVD", "api_key", fallback=None),
    }


def setup_logging(level_str: str) -> None:
    level = getattr(logging, level_str.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    # Suppress noisy third-party loggers
    for noisy in ("urllib3", "git.cmd", "github.Requester", "h5py._conv",
                  "tensorflow", "absl"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CVEfixes collector — Parquet/DuckDB backend"
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--sample",       action="store_true",
                      help="Fast sample collection (current year, 25 CVEs)")
    mode.add_argument("--update",       action="store_true",
                      help="Incremental weekly update (new CVEs only)")
    mode.add_argument("--catalog-only", action="store_true",
                      help="Rebuild DuckDB catalog without re-collecting")
    mode.add_argument("--reset",        action="store_true",
                      help="Clear checkpoint + staging files and restart from scratch")
    parser.add_argument("--parquet-base", default=None,
                        help="Override parquet base directory")
    parser.add_argument("--duckdb-path",  default=None,
                        help="Override DuckDB catalog path")
    args = parser.parse_args()

    config = load_config()
    setup_logging(config.get("logging_level", "INFO"))

    parquet_base = args.parquet_base or config.get("parquet_base", "parquet")
    duckdb_path  = args.duckdb_path  or config.get("duckdb_path", "cvefixes.duckdb")
    data_path    = config.get("data_path", "Data")
    github_user  = config.get("github_user")
    github_token = config.get("github_token")
    nvd_api_key  = config.get("nvd_api_key")
    num_workers  = config.get("num_workers", 4)
    sample_limit = 25 if args.sample else config.get("sample_limit", 0)

    if args.reset:
        checkpoint = Path(parquet_base) / "collection_state.json"
        staging_dir = Path(parquet_base) / "staging"
        removed: list[str] = []
        if checkpoint.exists():
            checkpoint.unlink()
            removed.append("collection_state.json")
        if staging_dir.exists():
            shutil.rmtree(staging_dir)
            removed.append("staging/")
        if removed:
            logging.info("Reset: removed %s", ", ".join(removed))
        else:
            logging.info("Reset: nothing to remove (already clean)")
        logging.info("Ready for a fresh collection run.  Re-run without --reset to start.")
        return

    if args.catalog_only:
        from storage.catalog import build_catalog
        logging.info("Rebuilding DuckDB catalog …")
        con = build_catalog(parquet_base, duckdb_path)
        con.close()
        logging.info("Done.")
        return

    if args.update:
        from update.merger import run_weekly_update
        run_weekly_update(
            data_path=data_path,
            parquet_base=parquet_base,
            duckdb_path=duckdb_path,
            github_user=github_user,
            github_token=github_token,
            nvd_api_key=nvd_api_key,
            sample_limit=sample_limit,
            num_workers=num_workers,
        )
    else:
        from update.merger import run_full_collection
        run_full_collection(
            data_path=data_path,
            parquet_base=parquet_base,
            duckdb_path=duckdb_path,
            github_user=github_user,
            github_token=github_token,
            nvd_api_key=nvd_api_key,
            sample_limit=sample_limit,
            num_workers=num_workers,
        )


if __name__ == "__main__":
    main()
