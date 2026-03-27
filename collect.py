#!/usr/bin/env python3
"""
CVEfixes collection entry point — Parquet/DuckDB backend.

Usage:
    # Full collection from scratch
    python collect.py

    # Sample collection (fast, current year only, 25 CVEs)
    python collect.py --sample

    # Weekly incremental update
    python collect.py --update

    # Just rebuild the DuckDB catalog (e.g. after manual Parquet edits)
    python collect.py --catalog-only
"""

from __future__ import annotations

import argparse
import logging
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
    num_workers  = config.get("num_workers", 4)
    sample_limit = 25 if args.sample else config.get("sample_limit", 0)

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
            sample_limit=sample_limit,
            num_workers=num_workers,
        )


if __name__ == "__main__":
    main()
