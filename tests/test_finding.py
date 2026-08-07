"""The Finding domain.

finding_from_dict and findings_from_list turn model output into Finding objects,
dropping an entry with no location and coercing a bad value to a safe default.
"""

from cyberjury.finding import finding_from_dict, findings_from_list


def test_finding_from_dict_maps_fields():
    """Exercise the finding from dict maps fields case."""
    f = finding_from_dict(
        {
            "file": "app.py",
            "line": 3,
            "severity": "high",
            "category": "sql_injection",
            "description": "concat",
            "exploit_scenario": "send ' OR 1=1",
            "confidence": 0.9,
        }
    )
    assert f.file == "app.py"
    assert f.line == 3
    assert f.severity == "HIGH"
    assert f.category == "sql_injection"
    assert f.confidence == 0.9


def test_finding_without_file_is_dropped():
    """Exercise the finding without file is dropped case."""
    assert finding_from_dict({"severity": "HIGH", "description": "x"}) is None


def test_finding_with_a_non_location_file_is_dropped():
    """Exercise the finding with a non location file is dropped case."""
    assert finding_from_dict({"file": ["a.py"], "severity": "HIGH"}) is None
    assert finding_from_dict({"file": {"path": "a.py"}}) is None
    assert finding_from_dict({"file": 123}) is None
    assert finding_from_dict({"file": "   "}) is None


def test_finding_coerces_bad_values():
    """Exercise the finding coerces bad values case."""
    f = finding_from_dict({"file": "a.py", "line": 0, "severity": "SCARY", "confidence": 5})
    assert f.line is None
    assert f.severity == "MEDIUM"
    assert f.confidence == 0.5


def test_findings_from_list_filters_bad_entries():
    """Exercise the findings from list filters bad entries case."""
    out = findings_from_list([{"file": "a.py"}, "not a dict", {"no": "file"}])
    assert len(out) == 1
    assert out[0].file == "a.py"
