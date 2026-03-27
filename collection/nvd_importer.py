"""
NVD CVE importer — downloads NVD JSON feeds and writes a staging Parquet.

Replaces the original Code/cve_importer.py.  No SQLite dependency.

Output: parquet/staging/cve_staging.parquet
        parquet/staging/fixes_staging.parquet  (repo commit links)
"""

from __future__ import annotations

import ast
import datetime
import json
import logging
import re
from io import BytesIO
from pathlib import Path
from typing import Any
from zipfile import ZipFile

import polars as pl
import requests
from pandas import json_normalize

logger = logging.getLogger("cvefixes.nvd_importer")

NVD_URL_HEAD = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-"
NVD_URL_TAIL = ".json.zip"
INIT_YEAR = 2002

GIT_COMMIT_RE = re.compile(
    r"(((?P<repo>(https|http)://(bitbucket|github|gitlab)\.(org|com)/(?P<owner>[^/]+)/(?P<project>[^/]*))"
    r"/(commit|commits)/(?P<hash>\w+)#?)+)"
)

# Columns from NVD JSON that we keep in the CVE table
_ORDERED_CVE_COLUMNS = [
    "cve_id", "published_date", "last_modified_date", "description",
    "severity", "cvss2_base_score", "cvss3_base_score",
    "reference_json", "problemtype_json",
]


def _rename_column(name: str) -> str:
    name = name.split(".", 2)[-1].replace(".", "_")
    name = re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()
    name = (name
            .replace("cvss_v", "cvss")
            .replace("_data", "_json")
            .replace("description_json", "description"))
    return name


def _download_year(year: int, json_dir: Path) -> Path:
    target_name = f"nvdcve-1.1-{year}.json"
    target_path = json_dir / target_name
    if target_path.exists():
        logger.info("Reusing cached %s NVD JSON", year)
        return target_path
    url = f"{NVD_URL_HEAD}{year}{NVD_URL_TAIL}"
    logger.info("Downloading NVD JSON for %s …", year)
    resp = requests.get(url, timeout=60)
    resp.raise_for_status()
    z = ZipFile(BytesIO(resp.content))
    z.extract(target_name, json_dir)
    return target_path


def _load_year(path: Path) -> list[dict]:
    with open(path) as fh:
        data = json.load(fh)
    return data.get("CVE_Items", [])


def _flatten_items(items: list[dict]) -> list[dict[str, Any]]:
    """Flatten a list of CVE_Item dicts into row dicts for Polars."""
    rows: list[dict[str, Any]] = []
    for item in items:
        cve = item.get("cve", {})
        cve_id = cve.get("CVE_data_meta", {}).get("ID", "")
        if not cve_id:
            continue

        # description
        desc_list = cve.get("description", {}).get("description_data", [])
        description = next(
            (d["value"] for d in desc_list if d.get("lang") == "en"), None
        )

        # references
        ref_list = cve.get("references", {}).get("reference_data", [])
        if not ref_list:
            continue  # skip CVEs without references

        # problem types
        pt_list = cve.get("problemtype", {}).get("problemtype_data", [])

        # CVSS
        impact = item.get("impact", {})
        v2 = impact.get("baseMetricV2", {})
        v3 = impact.get("baseMetricV3", {})
        severity_v2 = v2.get("cvssV2", {}).get("baseScore")
        severity_v3 = v3.get("cvssV3", {}).get("baseScore")

        # dates
        published_str = item.get("publishedDate", "")
        try:
            published_date = datetime.date.fromisoformat(published_str[:10])
        except (ValueError, TypeError):
            published_date = None

        rows.append({
            "cve_id": cve_id,
            "published_date": published_date,
            "severity_v2": float(severity_v2) if severity_v2 is not None else None,
            "severity_v3": float(severity_v3) if severity_v3 is not None else None,
            "description": description,
            "reference_json": json.dumps(ref_list),
            "problemtype_json": json.dumps(pt_list),
        })
    return rows


def _extract_fixes(df_cve: pl.DataFrame) -> pl.DataFrame:
    """
    Extract (cve_id, hash, repo_url) triples from reference_json column.
    """
    rows = []
    for row in df_cve.iter_rows(named=True):
        try:
            ref_list = json.loads(row["reference_json"])
        except (json.JSONDecodeError, TypeError):
            continue
        for ref in ref_list:
            url = ref.get("url", "")
            m = GIT_COMMIT_RE.search(url)
            if m:
                rows.append({
                    "cve_id": row["cve_id"],
                    "hash": m.group("hash"),
                    "repo_url": m.group("repo").replace("http:", "https:"),
                })
    if not rows:
        return pl.DataFrame({"cve_id": [], "hash": [], "repo_url": []})
    return pl.DataFrame(rows).unique()


def import_cves(
    data_path: str | Path,
    staging_path: str | Path,
    sample_limit: int = 0,
) -> tuple[pl.DataFrame, pl.DataFrame]:
    """
    Download NVD feeds, flatten, and write staging Parquets.

    Returns (df_cve, df_fixes) Polars DataFrames.

    Parameters
    ----------
    data_path:    directory for raw JSON cache
    staging_path: directory for output Parquet files
    sample_limit: if > 0, only collect current-year CVEs (for fast tests)
    """
    data_path = Path(data_path)
    staging_path = Path(staging_path)
    json_dir = data_path / "json"
    json_dir.mkdir(parents=True, exist_ok=True)
    staging_path.mkdir(parents=True, exist_ok=True)

    current_year = datetime.datetime.now().year
    init_year = current_year if sample_limit > 0 else INIT_YEAR

    all_rows: list[dict] = []
    for year in range(init_year, current_year + 1):
        path = _download_year(year, json_dir)
        items = _load_year(path)
        rows = _flatten_items(items)
        all_rows.extend(rows)
        logger.info("Year %d: %d CVE items loaded", year, len(rows))

    if not all_rows:
        logger.warning("No CVE rows collected")
        return pl.DataFrame(), pl.DataFrame()

    df_cve = (
        pl.DataFrame(all_rows)
        .unique(subset=["cve_id"])
        .sort("cve_id")
    )
    if sample_limit > 0:
        df_cve = df_cve.head(sample_limit)

    df_fixes = _extract_fixes(df_cve)
    if sample_limit > 0:
        # Filter out major repos that slow down sample collection
        _major = [
            "https://github.com/torvalds/linux",
            "https://github.com/ImageMagick/ImageMagick",
            "https://github.com/the-tcpdump-group/tcpdump",
            "https://github.com/phpmyadmin/phpmyadmin",
            "https://github.com/FFmpeg/FFmpeg",
        ]
        df_fixes = df_fixes.filter(~pl.col("repo_url").is_in(_major))
        df_fixes = df_fixes.head(sample_limit)

    cve_out = staging_path / "cve_staging.parquet"
    fixes_out = staging_path / "fixes_staging.parquet"
    df_cve.write_parquet(cve_out, compression="zstd")
    df_fixes.write_parquet(fixes_out, compression="zstd")
    logger.info("Wrote %d CVEs to %s", len(df_cve), cve_out)
    logger.info("Wrote %d fixes to %s", len(df_fixes), fixes_out)
    return df_cve, df_fixes
