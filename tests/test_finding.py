"""Finding parsing drops unlocated entries and coerces invalid values to safe defaults."""

from cyberjury.finding import finding_from_dict, findings_from_list


def test_finding_from_dict_maps_fields():
    """Finding from dict maps fields."""
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


def test_finding_provenance_stays_out_of_the_wire_form():
    """Provenance is internal metadata, not persisted report output."""
    from cyberjury.finding import Finding

    assert "found_by" not in Finding(file="app.py", found_by=("finder",)).to_dict()


def test_finding_without_file_is_dropped():
    """Finding without file is dropped."""
    assert finding_from_dict({"severity": "HIGH", "description": "x"}) is None


def test_finding_with_a_non_location_file_is_dropped():
    """Finding with a non location file is dropped."""
    assert finding_from_dict({"file": ["a.py"], "severity": "HIGH"}) is None
    assert finding_from_dict({"file": {"path": "a.py"}}) is None
    assert finding_from_dict({"file": 123}) is None
    assert finding_from_dict({"file": "   "}) is None


def test_finding_coerces_bad_values():
    """Finding coerces bad values."""
    f = finding_from_dict({"file": "a.py", "line": 0, "severity": "SCARY", "confidence": 5})
    assert f.line is None
    assert f.severity == "MEDIUM"
    assert f.confidence == 0.5


def test_findings_from_list_filters_bad_entries():
    """Findings from list filters bad entries."""
    out = findings_from_list([{"file": "a.py"}, "not a dict", {"no": "file"}])
    assert len(out) == 1
    assert out[0].file == "a.py"
