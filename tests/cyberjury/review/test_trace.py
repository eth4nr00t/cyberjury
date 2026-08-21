"""Review trace identities and sink isolation."""

from types import SimpleNamespace

from cyberjury.review.trace import emit_trace, finding_id


def test_finding_id_survives_path_and_category_normalization():
    """Equivalent normalized finding fields produce one diagnostic identity."""
    first = SimpleNamespace(
        file="a\\app.py",
        category="open_redirect",
        description="redirect",
        exploit_scenario="attacker controls URL",
        recommendation="escape the pattern",
    )
    second = SimpleNamespace(
        file="a/app.py",
        category="open-redirect",
        description=" redirect ",
        exploit_scenario="attacker controls URL",
        recommendation="escape the pattern",
    )

    assert finding_id(first) == finding_id(second)


def test_trace_sink_failure_does_not_escape():
    """A diagnostic sink failure cannot affect the review caller."""

    def fail(_event):
        raise OSError("trace path unavailable")

    emit_trace(fail, "review_finished", status="complete")
