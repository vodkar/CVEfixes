"""
NVD CVE importer — uses NVD REST API 2.0 (replaces retired 1.1 JSON feeds).

The legacy feeds at nvd.nist.gov/feeds/json/cve/1.1/ were retired on
December 15 2023 and now return HTTP 403.  This module uses the current
REST API at services.nvd.nist.gov/rest/json/cves/2.0.

API key
-------
Register for a free key at https://nvd.nist.gov/developers/request-an-api-key
and add it to your .CVEfixes.ini::

    [NVD]
    api_key = <your-key>

Without a key the API allows 5 requests / 30 s.  With a key: 50 / 30 s.

Output: parquet/staging/cve_staging.parquet
        parquet/staging/fixes_staging.parquet  (repo commit links)
"""

from __future__ import annotations

import datetime
import json
import logging
import re
import time
from pathlib import Path
from typing import Any

import polars as pl
import requests

logger = logging.getLogger("cvefixes.nvd_importer")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000
INIT_YEAR = 2002

# Delay between API requests to stay within rate limits.
# NVD recommends sleeping ≥6 s between requests without a key,
# and ≥0.6 s with a key.  We use 6 s for the no-key path and
# 0.7 s with a key (a small buffer above the minimum).
_SLEEP_NO_KEY = 6.0
_SLEEP_WITH_KEY = 0.7

GIT_COMMIT_RE = re.compile(
    r"(((?P<repo>(https|http)://(bitbucket|github|gitlab)\.(org|com)/(?P<owner>[^/]+)/(?P<project>[^/]*))"
    r"/(commit|commits)/(?P<hash>\w+)#?)+)"
)


# ---------------------------------------------------------------------------
# Low-level API fetching
# ---------------------------------------------------------------------------

def _build_headers(api_key: str | None) -> dict[str, str]:
    if api_key:
        return {"apiKey": api_key}
    return {}


def _fetch_page(
    start_index: int,
    pub_start: str,
    pub_end: str,
    api_key: str | None,
    session: requests.Session,
) -> dict:
    """Fetch one page of results from the NVD 2.0 API."""
    params: dict[str, Any] = {
        "pubStartDate": pub_start,
        "pubEndDate": pub_end,
        "resultsPerPage": RESULTS_PER_PAGE,
        "startIndex": start_index,
    }
    resp = session.get(
        NVD_API_URL,
        params=params,
        headers=_build_headers(api_key),
        timeout=60,
    )
    resp.raise_for_status()
    return resp.json()


def _download_year(year: int, json_dir: Path, api_key: str | None) -> list[dict]:
    """
    Return all CVE vulnerability objects for *year*.

    Results are cached as ``{json_dir}/nvdcve-2.0-{year}.json`` so
    repeated runs don't re-download the same data.
    """
    cache_path = json_dir / f"nvdcve-2.0-{year}.json"
    if cache_path.exists():
        logger.info("Reusing cached NVD API 2.0 data for %s", year)
        return json.loads(cache_path.read_text())

    logger.info("Downloading NVD API 2.0 data for %s …", year)
    pub_start = f"{year}-01-01T00:00:00.000"
    pub_end   = f"{year}-12-31T23:59:59.999"
    sleep_s   = _SLEEP_WITH_KEY if api_key else _SLEEP_NO_KEY

    all_vulns: list[dict] = []
    start_index = 0
    session = requests.Session()

    while True:
        data = _fetch_page(start_index, pub_start, pub_end, api_key, session)
        vulns = data.get("vulnerabilities", [])
        all_vulns.extend(vulns)
        total = data.get("totalResults", 0)
        start_index += len(vulns)
        logger.debug(
            "Year %d: fetched %d/%d CVEs (startIndex=%d)",
            year, len(all_vulns), total, start_index,
        )
        if start_index >= total or not vulns:
            break
        time.sleep(sleep_s)

    cache_path.write_text(json.dumps(all_vulns))
    return all_vulns


# ---------------------------------------------------------------------------
# Flattening API 2.0 response into row dicts
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
    Convert API 2.0 ``weaknesses`` to the legacy problemtype_json format
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
# Fix extraction (unchanged — parses reference_json for git commit URLs)
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
    nvd_api_key: str | None = None,
) -> tuple[pl.DataFrame, pl.DataFrame]:
    """
    Download CVEs from the NVD REST API 2.0, flatten, and write staging Parquets.

    Returns (df_cve, df_fixes) Polars DataFrames.

    Parameters
    ----------
    data_path:    directory for raw JSON cache
    staging_path: directory for output Parquet files
    sample_limit: if > 0, only collect current-year CVEs (for fast tests)
    nvd_api_key:  optional NVD API key (raises rate limit from 5 to 50 req/30s)
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
        vulns = _download_year(year, json_dir, nvd_api_key)
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
