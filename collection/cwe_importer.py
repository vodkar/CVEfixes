"""
CWE importer — downloads MITRE CWE XML and produces staging Parquets.

Replaces the original Code/extract_cwe_record.py.  No SQLite dependency.

Outputs:
    parquet/staging/cwe_staging.parquet
    parquet/staging/cwe_classification_staging.parquet
"""



import fnmatch
import json
import logging
import time
import xml.etree.ElementTree as ET
from io import BytesIO
from pathlib import Path
from urllib.request import urlopen
from zipfile import ZipFile

import polars as pl

logger = logging.getLogger("cvefixes.cwe_importer")

CWE_XML_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

# Synthetic CWE IDs used by NVD that are not in the official XML
_SYNTHETIC_CWES = [
    {
        "cwe_id": "NVD-CWE-noinfo",
        "cwe_name": "Insufficient Information",
        "description": (
            "There is insufficient information about the issue to classify it; "
            "details are unknown or unspecified."
        ),
        "extended_description": "Insufficient Information",
        "url": "https://nvd.nist.gov/vuln/categories",
        "is_category": False,
    },
    {
        "cwe_id": "NVD-CWE-Other",
        "cwe_name": "Other",
        "description": (
            "NVD is only using a subset of CWE for mapping instead of the entire CWE, "
            "and the weakness type is not covered by that subset."
        ),
        "extended_description": "Insufficient Information",
        "url": "https://nvd.nist.gov/vuln/categories",
        "is_category": False,
    },
]


def _download_cwe_xml(data_path: Path) -> ET.ElementTree:
    existing = sorted(data_path.glob("cwec_*.xml"))
    if existing:
        logger.info("Reusing cached CWE XML: %s", existing[-1])
        return ET.parse(existing[-1])

    logger.info("Downloading CWE XML from MITRE …")
    cwe_zip = ZipFile(BytesIO(urlopen(CWE_XML_URL).read()))
    names = sorted(fnmatch.filter(cwe_zip.namelist(), "cwec_*.xml"))
    assert names, "No cwec_*.xml found in MITRE zip"
    extracted = cwe_zip.extract(names[-1], data_path)
    time.sleep(2)  # polite delay after external download
    return ET.parse(extracted)


def _parse_cwe_xml(tree: ET.ElementTree) -> list[dict]:
    root = tree.getroot()
    rows: list[dict] = []
    # First two children are Weaknesses and Categories
    for cat_flag, parent in enumerate(root[0:2]):
        for node in parent:
            cwe_id = "CWE-" + node.attrib["ID"]
            cwe_name = node.attrib.get("Name")
            description_node = node[0] if len(node) > 0 else None
            description = description_node.text if description_node is not None else None
            ext_node = node[1] if len(node) > 1 else None
            if cat_flag == 1 or ext_node is None:
                extended_description = ""
            else:
                extended_description = ET.tostring(ext_node, encoding="unicode", method="text")
            node_id = int(node.attrib["ID"])
            url = (
                f"https://cwe.mitre.org/data/definitions/{node_id}.html"
                if node_id > 0 else None
            )
            rows.append({
                "cwe_id": cwe_id,
                "cwe_name": cwe_name,
                "description": description,
                "extended_description": extended_description,
                "url": url,
                "is_category": cat_flag == 1,
            })
    return rows


def _extract_cwe_ids_from_problemtype(problemtype_json_list: list[str]) -> list[list[str]]:
    """
    Parse problemtype_json strings (list of {description:[{value:CWE-xxx}]})
    and return a list of CWE ID lists, one per CVE.
    """
    result = []
    for raw in problemtype_json_list:
        try:
            pt_list = json.loads(raw) if isinstance(raw, str) else raw
        except (json.JSONDecodeError, TypeError):
            result.append(["NVD-CWE-noinfo"])
            continue
        cwe_ids = []
        for pt in pt_list:
            for desc in pt.get("description", []):
                val = desc.get("value", "")
                if val.startswith("CWE-") or val.startswith("NVD-CWE"):
                    cwe_ids.append(val)
        if not cwe_ids:
            cwe_ids = ["NVD-CWE-noinfo"]
        result.append(cwe_ids)
    return result


def import_cwes(
    data_path: str | Path,
    staging_path: str | Path,
    df_cve: "pl.DataFrame | None" = None,
    cve_staging_path: "str | Path | None" = None,
) -> tuple["pl.DataFrame", "pl.DataFrame"]:
    """
    Download CWE XML and build CWE + cwe_classification staging Parquets.

    Parameters
    ----------
    data_path:          directory for raw XML cache
    staging_path:       directory to write output Parquets
    df_cve:             already-loaded CVE DataFrame (optional)
    cve_staging_path:   path to cve_staging.parquet if df_cve not provided
    """
    data_path = Path(data_path)
    staging_path = Path(staging_path)
    staging_path.mkdir(parents=True, exist_ok=True)

    # Load CVE data to build classifications
    if df_cve is None:
        if cve_staging_path is None:
            cve_staging_path = staging_path / "cve_staging.parquet"
        df_cve = pl.read_parquet(cve_staging_path)

    # Parse CWE definitions
    tree = _download_cwe_xml(data_path)
    rows = _parse_cwe_xml(tree)
    rows.extend(_SYNTHETIC_CWES)

    df_cwe = (
        pl.DataFrame(rows)
        .unique(subset=["cwe_id"])
        .sort("cwe_id")
    )

    # Build classification table
    cve_ids = df_cve["cve_id"].to_list()
    problemtype_jsons = df_cve["problemtype_json"].to_list()
    cwe_id_lists = _extract_cwe_ids_from_problemtype(problemtype_jsons)

    classification_rows = []
    known_cwes = set(df_cwe["cwe_id"].to_list())
    for cve_id, cwe_ids in zip(cve_ids, cwe_id_lists):
        for cwe_id in cwe_ids:
            # Remap unknown CWE IDs to NVD-CWE-noinfo
            if cwe_id not in known_cwes:
                cwe_id = "NVD-CWE-noinfo"
            classification_rows.append({"cve_id": cve_id, "cwe_id": cwe_id})

    df_class = (
        pl.DataFrame(classification_rows)
        .unique(subset=["cve_id", "cwe_id"])
        .sort(["cve_id", "cwe_id"])
    )

    # Narrow CWE table to only referenced CWE IDs
    used_cwes = set(df_class["cwe_id"].to_list())
    df_cwe = df_cwe.filter(pl.col("cwe_id").is_in(used_cwes))

    cwe_out = staging_path / "cwe_staging.parquet"
    class_out = staging_path / "cwe_classification_staging.parquet"
    df_cwe.write_parquet(cwe_out, compression="zstd")
    df_class.write_parquet(class_out, compression="zstd")
    logger.info("Wrote %d CWEs to %s", len(df_cwe), cwe_out)
    logger.info("Wrote %d CWE classifications to %s", len(df_class), class_out)
    return df_cwe, df_class
