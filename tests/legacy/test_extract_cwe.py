"""
Tests for Code/extract_cwe_record.py

Covers:
- parse_cwes: string → list with whitespace stripping
- add_cwe_class: JSON problemtype_json → list of CWE ID lists
"""

import json
import pytest

from extract_cwe_record import parse_cwes, add_cwe_class


# ---------------------------------------------------------------------------
# parse_cwes
# ---------------------------------------------------------------------------

class TestParseCwes:
    def test_simple_list(self):
        assert parse_cwes("['CWE-119', 'CWE-120']") == ["CWE-119", "CWE-120"]

    def test_single_element(self):
        assert parse_cwes("['CWE-89']") == ["CWE-89"]

    def test_strips_whitespace(self):
        result = parse_cwes("['  CWE-79  ', ' CWE-89 ']")
        assert result == ["CWE-79", "CWE-89"]

    def test_empty_list(self):
        assert parse_cwes("[]") == []

    def test_nvd_synthetic_ids(self):
        result = parse_cwes("['NVD-CWE-noinfo']")
        assert result == ["NVD-CWE-noinfo"]


# ---------------------------------------------------------------------------
# add_cwe_class
# ---------------------------------------------------------------------------

def _pt_json(cwe_values):
    """Build a problemtype_json string matching the NVD nested format."""
    return json.dumps([{
        "description": [{"lang": "en", "value": v} for v in cwe_values]
    }])


class TestAddCweClass:
    def test_single_cwe(self):
        result = add_cwe_class([_pt_json(["CWE-119"])])
        assert result == [["CWE-119"]]

    def test_multiple_cwes_per_cve(self):
        result = add_cwe_class([_pt_json(["CWE-119", "CWE-120"])])
        assert result == [["CWE-119", "CWE-120"]]

    def test_empty_description_returns_unknown(self):
        # Empty description list → unknown
        pt = json.dumps([{"description": []}])
        result = add_cwe_class([pt])
        assert result == [["unknown"]]

    def test_multiple_cves(self):
        pt1 = _pt_json(["CWE-89"])
        pt2 = _pt_json(["CWE-79"])
        result = add_cwe_class([pt1, pt2])
        assert result == [["CWE-89"], ["CWE-79"]]

    def test_output_length_matches_input(self):
        pts = [_pt_json([f"CWE-{i}"]) for i in range(10)]
        result = add_cwe_class(pts)
        assert len(result) == 10

    def test_nvd_synthetic_id_preserved(self):
        result = add_cwe_class([_pt_json(["NVD-CWE-noinfo"])])
        assert result == [["NVD-CWE-noinfo"]]

    def test_mixed_empty_and_filled(self):
        pts = [
            _pt_json(["CWE-119"]),
            json.dumps([{"description": []}]),  # empty
            _pt_json(["CWE-89"]),
        ]
        result = add_cwe_class(pts)
        assert result[0] == ["CWE-119"]
        assert result[1] == ["unknown"]
        assert result[2] == ["CWE-89"]

    def test_single_quotes_in_json_handled(self):
        # The original code replaces single quotes with double quotes
        pt = str([{"description": [{"lang": "en", "value": "CWE-119"}]}])
        result = add_cwe_class([pt])
        assert result == [["CWE-119"]]
