"""Repository candidate parsing accepts only reportable in root locations."""

from cyberjury.review.repository.engine import (
    _parse_candidate,
)


def test_parse_candidate_captures_file_and_line_from_a_range(tmp_path):
    p = tmp_path / "i.md"
    p.write_text(
        "# freshness gap\n- Risk: HIGH\n- Type: replay\n- Source: `POST /v1/check`\n"
        "## Analysis\n`authorizer/controllers/registrar.py:58-75` no nonce.\n"
    )
    c = _parse_candidate(p)
    assert c.file == "authorizer/controllers/registrar.py"
    assert c.line == 58
    assert c.severity == "HIGH"


def test_parse_candidate_strips_a_finding_title_prefix(tmp_path):
    p = tmp_path / "i.md"
    p.write_text(
        "# Finding: Signing Key Committed to Source\n- Risk: LOW\n- Type: secret\n"
        "- Source: `GET /v1/key`\n## Analysis\n`app/keys.py:3` hardcoded.\n"
    )
    c = _parse_candidate(p)
    assert c.title == "Signing Key Committed to Source"


def test_parse_candidate_drops_an_out_of_root_cited_path(tmp_path):
    traversing = tmp_path / "t.md"
    traversing.write_text("# leak\n- Risk: HIGH\n- Type: idor\n## Analysis\nsee `../../etc/secret.py:1` for the key.\n")
    assert _parse_candidate(traversing) is None
    absolute = tmp_path / "a.md"
    absolute.write_text("# leak\n- Risk: HIGH\n- Type: idor\n## Analysis\nsee `/home/user/secret.py:1` for the key.\n")
    assert _parse_candidate(absolute) is None


def test_parse_candidate_drops_a_cleared_or_refuted_record(tmp_path):
    refuted = tmp_path / "r.md"
    refuted.write_text(
        "# Attachment IDOR, refuted\n- Status: refuted (no finding)\n- Type: idor\n"
        "## Why\n`pkg/models/task_attachment.go:111` xorm scopes the fetch.\n"
    )
    assert _parse_candidate(refuted) is None
    cleared = tmp_path / "c.md"
    cleared.write_text(
        "# Permission methods cleared\n- Status: cleared\n- Type: idor\n"
        "## Scope\n`pkg/models/task_attachment_permissions.go:25` holds.\n"
    )
    assert _parse_candidate(cleared) is None
    titled = tmp_path / "t.md"
    titled.write_text(
        "# Cleared controls and paths checked\n- Type:\n"
        "## Blacklist gate\n`pkg/models/token.go:82` adminSanity enforces it.\n"
    )
    assert _parse_candidate(titled) is None
    confirmed = tmp_path / "k.md"
    confirmed.write_text(
        "# real leak\n- Status: confirmed\n- Type: idor\n## Analysis\n`pkg/models/link_sharing.go:272` leaks hashes.\n"
    )
    assert _parse_candidate(confirmed) is not None


def test_parse_candidate_accepts_data_driven_extensions(tmp_path):
    go = tmp_path / "go.md"
    go.write_text(
        "# go handler idor\n- Risk: HIGH\n- Type: idor\n- Source: `GET /x`\n"
        "- Status: confirmed\n## Analysis\nsrc/handler.go:42 no owner check\n"
    )
    c = _parse_candidate(go)
    assert c is not None
    assert c.file == "src/handler.go"
    assert c.line == 42

    tsx = tmp_path / "tsx.md"
    tsx.write_text(
        "# react xss\n- Risk: MEDIUM\n- Type: xss\n- Source: `x`\n"
        "- Status: confirmed\n## Analysis\nweb/App.tsx:10 dangerouslySetInnerHTML\n"
    )
    c2 = _parse_candidate(tsx)
    assert c2 is not None
    assert c2.file == "web/App.tsx"
    assert c2.line == 10
