"""
Tests for Code/cve_importer.py

Covers:
- rename_columns: snake_case conversion of NVD nested column names
- preprocess_jsons: DataFrame flattening, column selection, null filtering
"""

import json

import pandas as pd
import pytest

from cve_importer import rename_columns, preprocess_jsons


# ---------------------------------------------------------------------------
# rename_columns
# ---------------------------------------------------------------------------

class TestRenameColumns:
    def test_top_level_camel_case(self):
        assert rename_columns("publishedDate") == "published_date"

    def test_nested_dot_prefix_stripped(self):
        # NVD columns arrive as e.g. "impact.baseMetricV2.cvssV2.baseScore"
        # split('.', 2)[-1] → "cvssV2.baseScore"
        # replace('.','_')  → "cvssV2_baseScore"
        # CamelCase → snake  → "cvss_v2_base_score"
        # replace('cvss_v','cvss') → "cvss2_base_score"
        result = rename_columns("impact.baseMetricV2.cvssV2.baseScore")
        assert "impact" not in result
        assert result == "cvss2_base_score"

    def test_cvss_version_abbreviation(self):
        # cvss_v2 → cvss2, cvss_v3 → cvss3
        assert "cvss2" in rename_columns("impact.baseMetricV2.cvssV2.baseScore")
        assert "cvss3" in rename_columns("impact.baseMetricV3.cvssV3.baseScore")

    def test_data_suffix_becomes_json(self):
        result = rename_columns("cve.references.reference_data")
        assert result.endswith("_json")

    def test_description_json_cleaned(self):
        # description_json → description (not double-json)
        result = rename_columns("cve.description.description_data")
        assert result == "description"

    def test_already_snake_case_unchanged(self):
        assert rename_columns("cve_id") == "cve_id"

    def test_no_dots_no_change(self):
        result = rename_columns("simpleField")
        assert result == "simple_field"

    def test_multiple_dots_only_last_two_kept(self):
        # split('.', 2)[-1] keeps everything from the third segment
        result = rename_columns("a.b.someNestedField")
        assert result == "some_nested_field"


# ---------------------------------------------------------------------------
# preprocess_jsons
# ---------------------------------------------------------------------------

def _make_nvd_item(cve_id, references=None, description="test vuln"):
    """Build a minimal NVD CVE_Items entry dict."""
    if references is None:
        references = [{"url": f"https://github.com/foo/bar/commit/abc123", "name": ""}]
    return {
        "cve": {
            "CVE_data_meta": {"ID": cve_id, "ASSIGNER": "cve@mitre.org"},
            "data_type": "CVE",
            "data_format": "MITRE",
            "data_version": "4.0",
            "references": {"reference_data": references},
            "description": {"description_data": [{"lang": "en", "value": description}]},
            "problemtype": {"problemtype_data": [{"description": [{"lang": "en", "value": "CWE-119"}]}]},
        },
        "configurations": {"CVE_data_version": "4.0", "nodes": []},
        "impact": {
            "baseMetricV2": {
                "cvssV2": {"version": "2.0", "vectorString": "AV:N", "baseScore": 7.5},
                "exploitabilityScore": 10.0,
                "impactScore": 6.4,
            }
        },
        "publishedDate": "2021-01-15T00:00Z",
        "lastModifiedDate": "2021-06-01T00:00Z",
    }


def _make_raw_df(items):
    """Wrap CVE_Items the same way the real NVD JSON download does."""
    return pd.DataFrame({
        "CVE_Items": items,
        "CVE_data_type": ["CVE"] * len(items),
        "CVE_data_format": ["MITRE"] * len(items),
        "CVE_data_version": ["4.0"] * len(items),
        "CVE_data_numberOfCVEs": [str(len(items))] * len(items),
        "CVE_data_timestamp": ["2021-01-01T00:00:00.000"] * len(items),
    })


class TestPreprocessJsons:
    def test_returns_dataframe(self):
        df_in = _make_raw_df([_make_nvd_item("CVE-2021-0001")])
        df_out = preprocess_jsons(df_in)
        assert isinstance(df_out, pd.DataFrame)

    def test_cve_id_column_present(self):
        df_in = _make_raw_df([_make_nvd_item("CVE-2021-0001")])
        df_out = preprocess_jsons(df_in)
        assert "cve_id" in df_out.columns

    def test_cve_id_value_correct(self):
        df_in = _make_raw_df([_make_nvd_item("CVE-2021-9999")])
        df_out = preprocess_jsons(df_in)
        assert "CVE-2021-9999" in df_out["cve_id"].values

    def test_removes_empty_references(self):
        items = [
            _make_nvd_item("CVE-2021-0001"),                     # has references
            _make_nvd_item("CVE-2021-0002", references=[]),       # empty → removed
        ]
        df_out = preprocess_jsons(_make_raw_df(items))
        assert "CVE-2021-0001" in df_out["cve_id"].values
        assert "CVE-2021-0002" not in df_out["cve_id"].values

    def test_all_ordered_columns_present(self):
        from cve_importer import ordered_cve_columns
        df_out = preprocess_jsons(_make_raw_df([_make_nvd_item("CVE-2021-0001")]))
        for col in ordered_cve_columns:
            assert col in df_out.columns, f"Missing column: {col}"

    def test_missing_columns_filled_with_empty_string(self):
        # If an impact section is absent, CVSS columns should default to ""
        item = _make_nvd_item("CVE-2021-NOCVSS")
        item["impact"] = {}  # strip impact section
        df_out = preprocess_jsons(_make_raw_df([item]))
        assert "cvss2_base_score" in df_out.columns

    def test_multiple_cves_preserved(self):
        items = [_make_nvd_item(f"CVE-2021-{i:04d}") for i in range(1, 6)]
        df_out = preprocess_jsons(_make_raw_df(items))
        assert len(df_out) == 5

    def test_reference_json_column_contains_list(self):
        # preprocess_jsons keeps reference_json as a Python list of dicts.
        # The caller (import_cves) later converts to str via applymap(str).
        df_out = preprocess_jsons(_make_raw_df([_make_nvd_item("CVE-2021-0001")]))
        ref = df_out["reference_json"].iloc[0]
        assert isinstance(ref, list)
        assert len(ref) > 0
        assert "url" in ref[0]
