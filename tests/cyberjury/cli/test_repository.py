"""Repository commands preserve lifecycle, mode, and completion semantics."""

import json
from types import SimpleNamespace

import pytest

import cyberjury.cli as climod
from cyberjury.cli import main
from cyberjury.providers.mock import MockProvider


def test_repository_help_says_run_scaffolds_automatically(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["review", "repository", "--help"])
    assert exc.value.code == 0
    output = " ".join(capsys.readouterr().out.split())
    assert "--run performs this setup automatically" in output
    assert "prerequisite for --run" not in output


def test_review_repository_writes_methodology_to_workspace(tmp_path):
    repository = tmp_path / "svc"
    repository.mkdir()
    (repository / "app.py").write_text("x = 1\n")
    ws = tmp_path / "ws"
    rc = main(["review", "repository", str(repository), "--workspace", str(ws), "--scaffold"])
    assert rc == 0
    assert (ws / "svc" / "methodology.md").is_file()


def test_review_repository_requires_a_mode(tmp_path):
    repository = tmp_path / "svc"
    repository.mkdir()
    (repository / "app.py").write_text("x = 1\n")
    ws = tmp_path / "ws"
    with pytest.raises(SystemExit) as exc:
        main(["review", "repository", str(repository), "--workspace", str(ws)])
    assert exc.value.code == 2


def test_review_repository_facts_writes_no_grounding_for_a_tree_with_no_definitions(tmp_path):
    repository = tmp_path / "svc"
    repository.mkdir()
    (repository / "app.py").write_text("x = 1\n")
    ws = tmp_path / "ws"
    rc = main(["review", "repository", str(repository), "--workspace", str(ws), "--scaffold"])
    assert rc == 0
    assert not (ws / "svc" / "_facts.md").exists()


def _graphable(root):
    root.mkdir()
    (root / "app.py").write_text("def handle(req):\n    return lookup(req)\n")
    (root / "store.py").write_text("def lookup(key):\n    return key\n")
    return root


def test_review_repository_grounds_the_web_profile(tmp_path):
    """Automatic web selection must bind tree-sitter before scaffold builds units."""
    ws = tmp_path / "ws"
    rc = main(["review", "repository", str(_graphable(tmp_path / "svc")), "--workspace", str(ws), "--scaffold"])
    assert rc == 0
    assert (ws / "svc" / "_facts.md").is_file()
    assert (ws / "svc" / "_facts_graph.json").is_file()


def _flask_repository(root):
    root.mkdir()
    (root / "app.py").write_text(
        "from flask import Flask, request\napp = Flask(__name__)\n"
        '@app.route("/x/<i>")\ndef h(i):\n    return request.args.get("y", "")\n'
    )
    (root / "requirements.txt").write_text("Flask==3.0\n")
    return root


def test_repository_gate_exits_nonzero_until_a_run_completes(tmp_path):
    repository = _flask_repository(tmp_path / "svc")
    ws = tmp_path / "ws"
    assert main(["review", "repository", str(repository), "--workspace", str(ws), "--gate"]) == 1
    assert main(["review", "repository", str(repository), "--workspace", str(ws), "--run", "--dry-run"]) == 0
    assert main(["review", "repository", str(repository), "--workspace", str(ws), "--gate"]) == 0


def test_repository_mode_flags_are_mutually_exclusive(tmp_path, capsys):
    repository = _flask_repository(tmp_path / "svc")
    ws = tmp_path / "ws"
    for combo in (["--run", "--gate"], ["--run", "--finalize"], ["--finalize", "--gate"]):
        with pytest.raises(SystemExit) as exc:
            main(["review", "repository", str(repository), "--workspace", str(ws), *combo])
        assert exc.value.code == 2
        assert "not allowed with argument" in capsys.readouterr().err
    assert not (ws / "svc" / "findings.json").exists()


def test_repository_run_with_model_errors_exits_nonzero(tmp_path, monkeypatch):
    repository = _flask_repository(tmp_path / "svc")
    ws = tmp_path / "ws"
    monkeypatch.setattr(
        "cyberjury.providers.configuration.make_provider",
        lambda *a, **k: MockProvider(default="not json at all"),
    )
    rc = main(
        [
            "review",
            "repository",
            str(repository),
            "--workspace",
            str(ws),
            "--run",
            "--api-key",
            "x",
        ]
    )
    assert rc == 1


def test_finalize_wires_challenger_skeptic_and_judge_confirmer(monkeypatch, tmp_path):
    import cyberjury.review.repository.engine as eng
    from cyberjury.review.verification import ModelRefutationChecker, ModelVerifier

    captured = {}

    def fake_finalize(target, workspace, *, options):
        captured["verifier"] = options.verification.verifier
        captured["confirmers"] = options.verification.confirmers
        return _finalize_result(tmp_path)

    monkeypatch.setattr(eng, "finalize_repository_review", fake_finalize)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    rc = main(
        [
            "review",
            "repository",
            str(tmp_path),
            "--finalize",
            "--api-key",
            "basekey",
            "--challenger-provider",
            "openai",
            "--challenger-model",
            "gpt-x",
            "--challenger-api-key",
            "k",
            "--judge-provider",
            "anthropic",
            "--judge-model",
            "claude-x",
            "--judge-api-key",
            "k2",
        ]
    )
    assert rc == 0
    assert isinstance(captured["verifier"], ModelVerifier)
    assert captured["verifier"]._model == "gpt-x"
    ((label, checker),) = captured["confirmers"]
    assert label == "claude-x"
    assert isinstance(checker, ModelRefutationChecker)
    assert checker._model == "claude-x"


def test_finalize_default_has_no_confirmer_and_notes_keep_all(monkeypatch, tmp_path, capsys):
    import cyberjury.review.repository.engine as eng

    def fake_finalize(target, workspace, *, options):
        fake_finalize.confirmers = options.verification.confirmers
        fake_finalize.poc_backend = options.output.poc_backend
        return _finalize_result(tmp_path)

    monkeypatch.setattr(eng, "finalize_repository_review", fake_finalize)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    rc = main(["review", "repository", str(tmp_path), "--finalize"])
    assert rc == 0
    assert fake_finalize.confirmers == []
    assert fake_finalize.poc_backend is not None
    out = capsys.readouterr()
    assert "keep-all" in out.err
    assert "PoC reconciliation" not in out.out


def test_finalize_closes_api_verifier_and_poc_providers(monkeypatch, tmp_path):
    import cyberjury.review.repository.engine as eng

    class ProviderWithClose(MockProvider):
        def __init__(self):
            super().__init__(default='{"real": true, "reason": ""}')
            self.closed = 0

        def close(self):
            self.closed += 1

    providers = []

    def fake_role_provider(args, spec):
        provider = ProviderWithClose()
        providers.append(provider)
        return provider

    monkeypatch.setattr(climod, "_role_provider", fake_role_provider)
    monkeypatch.setattr(eng, "finalize_repository_review", lambda *a, **k: _finalize_result(tmp_path))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    assert main(["review", "repository", str(tmp_path), "--finalize"]) == 0
    assert [p.closed for p in providers] == [1, 1]


def test_run_closes_api_role_verifier_and_poc_providers(monkeypatch, tmp_path):
    import cyberjury.review.repository.engine as eng

    class ProviderWithClose(MockProvider):
        def __init__(self):
            super().__init__(default='{"findings": []}')
            self.closed = 0

        def close(self):
            self.closed += 1

    providers = []

    def fake_role_provider(args, spec):
        provider = ProviderWithClose()
        providers.append(provider)
        return provider

    def fake_run(target, workspace, *, options):
        fake_run.poc_backend = options.output.poc_backend
        verify = SimpleNamespace(confirmed=[], refuted=[], errors=0, unlocatable=[])
        acc = SimpleNamespace(findings=[], new_per_pass=[[]], converged=True, errors=0)
        scaffold = SimpleNamespace(fallback_note="", workspace=str(tmp_path))
        return SimpleNamespace(scaffold=scaffold, accumulator=acc, verify=verify, units=1)

    monkeypatch.setattr(climod, "_role_provider", fake_role_provider)
    monkeypatch.setattr(eng, "run_repository_review", fake_run)
    assert main(["review", "repository", str(tmp_path), "--run", "--mode", "adversarial", "--api-key", "k"]) == 0
    assert fake_run.poc_backend is not None
    assert len(providers) == 5
    assert [p.closed for p in providers] == [1, 1, 1, 1, 1]


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        (["--api-key", "k"], 8),
        (["--api-key", "k", "--concurrency", "4"], 4),
    ],
)
def test_finalize_concurrency_uses_the_api_default(monkeypatch, tmp_path, args, expected):
    import cyberjury.review.repository.engine as eng

    captured = {}

    def fake_finalize(target, workspace, *, options):
        captured["concurrency"] = options.verification.concurrency
        return _finalize_result(tmp_path)

    monkeypatch.setattr(eng, "finalize_repository_review", fake_finalize)
    assert main(["review", "repository", str(tmp_path), "--finalize", *args]) == 0
    assert captured["concurrency"] == expected


def test_finalize_mentions_pocs_only_when_the_file_exists(monkeypatch, tmp_path, capsys):
    import cyberjury.review.repository.engine as eng

    monkeypatch.setattr(eng, "finalize_repository_review", lambda *a, **k: _finalize_result(tmp_path))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    (tmp_path / "_pocs.md").write_text("# PoC Reconciliation\n", encoding="utf-8")
    main(["review", "repository", str(tmp_path), "--finalize"])
    assert f"PoC reconciliation in {tmp_path}/_pocs.md" in capsys.readouterr().out


def _patch_run(monkeypatch, tmp_path, *, converged, errors, failure_reason=""):
    from types import SimpleNamespace

    import cyberjury.review.repository.engine as eng

    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")

    def fake_run(target, workspace, **kw):
        scaffold = SimpleNamespace(fallback_note="", workspace=str(tmp_path))
        acc = SimpleNamespace(findings=[], new_per_pass=[[]], converged=converged, errors=errors)
        outcome = SimpleNamespace(findings=[], degraded=bool(errors) or not converged, failure_reason=failure_reason)
        return SimpleNamespace(scaffold=scaffold, accumulator=acc, verify=None, units=1, outcome=outcome)

    monkeypatch.setattr(eng, "run_repository_review", fake_run)


def test_run_with_failed_calls_exits_nonzero_and_warns(monkeypatch, tmp_path, capsys):
    _patch_run(
        monkeypatch,
        tmp_path,
        converged=True,
        errors=2,
        failure_reason="RuntimeError: provider rate limited",
    )
    rc = main(["review", "repository", str(tmp_path), "--run", "--mode", "adversarial"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "model calls failed" in err
    assert "RuntimeError: provider rate limited" in err
    assert "did not converge" not in err


def test_run_that_did_not_converge_exits_nonzero_and_warns(monkeypatch, tmp_path, capsys):
    _patch_run(monkeypatch, tmp_path, converged=False, errors=0)
    rc = main(["review", "repository", str(tmp_path), "--run", "--mode", "adversarial"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "did not converge" in err
    assert "model calls failed" not in err


def test_finalize_verify_errors_exit_nonzero_and_ask_to_resume(monkeypatch, tmp_path, capsys):
    from types import SimpleNamespace

    import cyberjury.review.repository.engine as eng

    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")

    def fake_finalize(target, workspace, **kw):
        verify = SimpleNamespace(confirmed=[], refuted=[], errors=1)
        outcome = SimpleNamespace(complete=False)
        return SimpleNamespace(parsed=0, deduped=0, workspace=str(tmp_path), verify=verify, outcome=outcome)

    monkeypatch.setattr(eng, "finalize_repository_review", fake_finalize)
    rc = main(["review", "repository", str(tmp_path), "--finalize"])
    assert rc == 1
    assert "Re-run to resume" in capsys.readouterr().err


def test_unlocatable_warning_uses_singular_finding(capsys):
    climod._warn_unlocatable(SimpleNamespace(unlocatable=[SimpleNamespace(title="ghost", file="ghost.py")]))
    err = capsys.readouterr().err
    assert "1 finding cites" in err
    assert "so it was kept" in err


def test_run_passes_confirmers_and_no_extra_finders(monkeypatch, tmp_path):
    captured = _capture_run(monkeypatch)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    main(
        [
            "review",
            "repository",
            str(tmp_path),
            "--run",
            "--api-key",
            "basekey",
            "--challenger-provider",
            "openai",
            "--challenger-model",
            "gpt-x",
            "--challenger-api-key",
            "k",
        ]
    )
    assert captured["options"].roles.extra_finder_backends == ()
    labels = [label for label, _ in captured["options"].verification.confirmers]
    assert len(labels) == 1
    assert labels[0] != "gpt-x"


def test_executor_flag_is_removed(tmp_path, capsys):
    with pytest.raises(SystemExit) as exc:
        main(["review", "repository", str(tmp_path), "--finalize", "--reviewer", "model"])
    assert exc.value.code == 2
    assert "--reviewer" in capsys.readouterr().err
    with pytest.raises(SystemExit) as exc:
        main(["review", "repository", str(tmp_path), "--finalize", "--executor", "api"])
    assert exc.value.code == 2
    assert "--executor" in capsys.readouterr().err


@pytest.mark.parametrize(
    "args",
    [
        ["review", "diff", "--exclude", "vendor/"],
        ["review", "diff", "--source-meta", "target/cyberjury-source.json"],
        ["review", "diff", "--no-filter"],
        ["review", "diff", "--fail-on", "high"],
        ["review", "diff", "--executor", "api"],
        ["review", "repository", ".", "--run", "--effort", "high"],
        ["review", "repository", ".", "--run", "--min-lens-shots", "2"],
        ["review", "repository", ".", "--run", "--max-passes", "2"],
        ["review", "repository", ".", "--run", "--converge-after", "2"],
        ["review", "repository", ".", "--run", "--votes", "2"],
        ["review", "repository", ".", "--run", "--max-units", "10"],
        ["review", "repository", ".", "--scaffold", "--invariants", "rules.md"],
        ["review", "repository", ".", "--run", "--no-verify"],
        ["review", "repository", ".", "--gate", "--strict-coverage"],
        ["review", "repository", ".", "--finalize", "--poc"],
    ],
)
def test_removed_cli_flags_are_rejected(args, capsys):
    with pytest.raises(SystemExit) as exc:
        main(args)
    assert exc.value.code == 2
    active_modes = {"--run", "--scaffold", "--gate", "--finalize"}
    rejected = next(arg for arg in reversed(args) if arg.startswith("--") and arg not in active_modes)
    assert rejected in capsys.readouterr().err


def test_timeout_flag_is_accepted(tmp_path):
    repository = _flask_repository(tmp_path / "svc")
    ws = tmp_path / "ws"
    assert (
        main(["review", "repository", str(repository), "--workspace", str(ws), "--run", "--dry-run", "--timeout", "5"])
        == 0
    )


def test_auto_concurrency_defaults_to_eight():
    assert climod._auto_concurrency(None) == 8
    assert climod._auto_concurrency(4) == 4


def _finalize_result(tmp_path):
    from types import SimpleNamespace

    return SimpleNamespace(
        parsed=0,
        deduped=0,
        workspace=str(tmp_path),
        verify=None,
        outcome=SimpleNamespace(complete=True),
    )


def _capture_run(monkeypatch):
    import cyberjury.review.repository.engine as eng

    captured = {}
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")

    def fake_run(target, workspace, **kw):
        captured.update(kw)
        raise RuntimeError("stop after capture")

    monkeypatch.setattr(eng, "run_repository_review", fake_run)
    return captured


def test_repository_adversarial_rounds_flow_into_the_run(monkeypatch, tmp_path):
    """Repository adversarial rounds use the shared depth flag."""
    captured = _capture_run(monkeypatch)
    main(["review", "repository", str(tmp_path), "--run", "--mode", "adversarial", "--rounds", "5"])
    options = captured["options"]
    assert options.roles.mode == "adversarial"
    assert options.execution.max_passes == 5
    assert options.verification.votes == 1
    assert options.roles.challenger_provider is not None
    assert options.roles.judge_provider is not None


def test_repository_standard_mode_runs_one_round(monkeypatch, tmp_path):
    """Repository standard mode matches the single finder default."""
    captured = _capture_run(monkeypatch)
    main(["review", "repository", str(tmp_path), "--run"])
    options = captured["options"]
    assert options.roles.mode == "standard"
    assert options.execution.max_passes == 1
    assert options.roles.challenger_provider is None
    assert options.roles.judge_provider is None


def test_run_defaults_concurrency_to_eight(monkeypatch, tmp_path):
    captured = _capture_run(monkeypatch)
    main(["review", "repository", str(tmp_path), "--run"])
    assert captured["options"].execution.concurrency == 8
    assert captured["options"].verification.concurrency == 8


def test_explicit_concurrency_overrides_the_backend_default(monkeypatch, tmp_path):
    captured = _capture_run(monkeypatch)
    main(["review", "repository", str(tmp_path), "--run", "--concurrency", "9"])
    assert captured["options"].execution.concurrency == 9
    assert captured["options"].verification.concurrency == 9


def test_repository_stages_record_a_whole_pipeline_timeline(tmp_path):
    from cyberjury.telemetry import TIMELINE_FILE

    repo = tmp_path / "svc"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n")
    ws = tmp_path / "ws"
    timeline = ws / "svc" / TIMELINE_FILE

    main(["review", "repository", str(repo), "--workspace", str(ws), "--scaffold"])
    assert [r["stage"] for r in json.loads(timeline.read_text())] == ["scaffold"]

    main(["review", "repository", str(repo), "--workspace", str(ws), "--gate"])
    stages = json.loads(timeline.read_text())
    assert [r["stage"] for r in stages] == ["scaffold", "gate"]
    assert all(r["ok"] and isinstance(r["seconds"], (int, float)) for r in stages)

    main(["review", "repository", str(repo), "--workspace", str(ws), "--scaffold"])
    assert [r["stage"] for r in json.loads(timeline.read_text())] == ["scaffold"]
