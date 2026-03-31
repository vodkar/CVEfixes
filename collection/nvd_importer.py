"""
NVD CVE importer — downloads NVD JSON 2.0 feeds and writes staging Parquets.

Feed URL: https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.zip

The legacy 1.1 feeds (nvdcve-1.1-{year}.json.zip) were retired on
2023-12-15 and return HTTP 403.  The 2.0 feeds use the same zip-per-year
layout but a different JSON schema:

    {
        "vulnerabilities": [
            {"cve": {"id": "CVE-...", "published": "...", "metrics": {...},
                     "weaknesses": [...], "references": [...], ...}},
            ...
        ]
    }

Output: parquet/staging/cve_staging.parquet
        parquet/staging/fixes_staging.parquet  (repo commit links)
"""

from __future__ import annotations

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

logger = logging.getLogger("cvefixes.nvd_importer")

NVD_FEED_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-"
NVD_FEED_EXT = ".json.zip"
INIT_YEAR = 2002

GIT_COMMIT_RE = re.compile(
    r"(((?P<repo>(https|http)://(bitbucket|github|gitlab)\.(org|com)/(?P<owner>[^/]+)/(?P<project>[^/]*))"
    r"/(commit|commits)/(?P<hash>\w+)#?)+)"
)


# ---------------------------------------------------------------------------
# Download and cache
# ---------------------------------------------------------------------------

def _download_year(year: int, json_dir: Path) -> Path:
    target_name = f"nvdcve-2.0-{year}.json"
    target_path = json_dir / target_name
    if target_path.exists():
        logger.info("Reusing cached NVD 2.0 JSON for %s", year)
        return target_path
    url = f"{NVD_FEED_URL}{year}{NVD_FEED_EXT}"
    logger.info("Downloading NVD 2.0 JSON for %s …", year)
    resp = requests.get(url, timeout=60)
    resp.raise_for_status()
    z = ZipFile(BytesIO(resp.content))
    z.extract(target_name, json_dir)
    return target_path


def _load_year(path: Path) -> list[dict]:
    with open(path) as fh:
        data = json.load(fh)
    if "vulnerabilities" not in data:
        raise KeyError(f"'vulnerabilities' key missing in NVD 2.0 JSON file: {path}")
    return data["vulnerabilities"]


# ---------------------------------------------------------------------------
# Flattening NVD 2.0 schema into row dicts
# ---------------------------------------------------------------------------

def _get_score_v2(metrics: dict) -> float | None:
    for entry in metrics.get("cvssMetricV2", []):
        score = entry.get("cvssData", {}).get("baseScore")
        if score is not None:
            return float(score)
    return None


def _get_score_v3(metrics: dict) -> float | None:
    for key in ("cvssMetricV31", "cvssMetricV30"):
        for entry in metrics.get(key, []):
            score = entry.get("cvssData", {}).get("baseScore")
            if score is not None:
                return float(score)
    return None


def _weaknesses_to_problemtype_json(weaknesses: list[dict]) -> str:
    """
    Convert NVD 2.0 ``weaknesses`` to the legacy problemtype_json format
    expected by cwe_importer._extract_cwe_ids_from_problemtype:

        [{"description": [{"value": "CWE-xxx"}]}, ...]
    """
    pt_list = []
    for w in weaknesses:
        descs = [
            {"value": d["value"]}
            for d in w.get("description", [])
            if d.get("lang") == "en"
        ]
        if descs:
            pt_list.append({"description": descs})
    return json.dumps(pt_list)


def _flatten_vulns(vulns: list[dict]) -> list[dict[str, Any]]:
    """Flatten a list of NVD 2.0 vulnerability objects into row dicts."""
    rows: list[dict[str, Any]] = []
    for vuln in vulns:
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            continue

        # description (English)
        description = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            None,
        )

        # references
        ref_list = [{"url": r["url"]} for r in cve.get("references", [])]
        if not ref_list:
            continue  # skip CVEs without references

        # problem types (CWEs) — kept in legacy format for cwe_importer
        problemtype_json = _weaknesses_to_problemtype_json(cve.get("weaknesses", []))

        # CVSS scores
        metrics = cve.get("metrics", {})
        severity_v2 = _get_score_v2(metrics)
        severity_v3 = _get_score_v3(metrics)

        # published date
        published_str = cve.get("published", "")
        try:
            published_date = datetime.date.fromisoformat(published_str[:10])
        except (ValueError, TypeError):
            published_date = None

        rows.append({
            "cve_id": cve_id,
            "published_date": published_date,
            "severity_v2": severity_v2,
            "severity_v3": severity_v3,
            "description": description,
            "reference_json": json.dumps(ref_list),
            "problemtype_json": problemtype_json,
        })
    return rows


# ---------------------------------------------------------------------------
# Fix extraction (parses reference_json for git commit URLs)
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def import_cves(
    data_path: str | Path,
    staging_path: str | Path,
    sample_limit: int = 0,
) -> tuple[pl.DataFrame, pl.DataFrame]:
    """
    Download NVD 2.0 JSON feeds, flatten, and write staging Parquets.

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
        vulns = _load_year(path)
        rows = _flatten_vulns(vulns)
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
