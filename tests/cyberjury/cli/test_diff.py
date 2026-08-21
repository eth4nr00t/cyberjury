"""Diff commands preserve profile selection, failure reporting, and verification wiring."""

import io
import os
import subprocess
from types import SimpleNamespace

import pytest

import cyberjury.cli as climod
from cyberjury.cli import main
from cyberjury.providers.mock import MockProvider
from cyberjury.review.failures import ReviewUnitFailure

_FILE_A = "diff --git a/a.py b/a.py\n@@ -0,0 +1 @@\n+x = 1\n"

_DIFF = _FILE_A


def test_review_diff_dry_run_is_zero_config(capsys):
    rc = main(["review", "diff", "--dry-run"])
    assert rc == 0
    assert "sql-injection" in capsys.readouterr().out


def test_review_diff_help_exposes_the_profile_flag(capsys):
    """The canonical selector must be discoverable without advertising removed syntax."""
    with pytest.raises(SystemExit) as exc:
        main(["review", "diff", "--help"])
    assert exc.value.code == 0
    output = capsys.readouterr().out
    assert "--profile PROFILE" in output
    assert "--domain" not in output


def test_review_diff_rejects_the_removed_domain_flag(capsys):
    """Removed syntax must fail instead of silently selecting the default profile."""
    with pytest.raises(SystemExit) as exc:
        main(["review", "diff", "--domain", "web", "--dry-run"])
    assert exc.value.code == 2
    assert "unrecognized arguments: --domain web" in capsys.readouterr().err


def test_review_diff_auto_profile_parses_quoted_solidity_path(tmp_path):
    patch = tmp_path / "quoted.diff"
    patch.write_text(
        'diff --git "a/Token Contract.sol" "b/Token Contract.sol"\n'
        '--- "a/Token Contract.sol"\n'
        '+++ "b/Token Contract.sol"\n'
        "@@ -1 +1 @@\n-old\n+new\n"
    )

    state = climod._prepare_diff_command(
        SimpleNamespace(
            dry_run=True,
            file=str(patch),
            git_range=None,
            profile="auto",
        )
    )

    assert state.profile.name == "evm"


def _git(cwd, *args):
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "Test",
        "GIT_AUTHOR_EMAIL": "test@example.com",
        "GIT_COMMITTER_NAME": "Test",
        "GIT_COMMITTER_EMAIL": "test@example.com",
    }
    return subprocess.run(
        ["git", "-C", str(cwd), *args], check=True, capture_output=True, text=True, env=env
    ).stdout.strip()


def test_diff_source_root_uses_git_range_ref(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "--quiet")
    (repo / "app.py").write_text("old\n")
    _git(repo, "add", "app.py")
    _git(repo, "commit", "--quiet", "-m", "old")
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "app.py").write_text("new\n")
    _git(repo, "commit", "--quiet", "-am", "new")
    ref = _git(repo, "rev-parse", "HEAD")

    args = SimpleNamespace(repository=str(repo), git_range=f"{base}..{ref}")
    with climod._diff_source_root(args) as root:
        assert (root / "app.py").read_text() == "new\n"
        worktree = root

    assert not worktree.exists()


def test_review_diff_closes_its_backends(monkeypatch, tmp_path):
    closed = []

    class _Spy:
        def close(self):
            closed.append(True)

    spy = _Spy()
    monkeypatch.setattr(
        climod,
        "_build_diff_providers",
        lambda args: climod.DiffProviders(base_provider=spy, base_model="mock"),
    )
    monkeypatch.setattr(
        climod,
        "run_diff_review",
        lambda *a, **k: SimpleNamespace(outcome=SimpleNamespace(findings=[], failures=[], degraded=False)),
    )
    diff = tmp_path / "c.diff"
    diff.write_text("--- a/x.py\n+++ b/x.py\n@@ -0,0 +1 @@\n+x = 1\n")
    assert main(["review", "diff", "--file", str(diff)]) == 0
    assert closed == [True]


def test_close_backends_dedupes_same_object_by_identity():
    closed = []

    class _Spy:
        def close(self):
            closed.append(True)

    spy = _Spy()
    climod._close_backends(spy, spy, None)
    assert closed == [True]


def test_review_diff_repository_backed_file_collects_context_and_verifies(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    diff = tmp_path / "c.diff"
    diff.write_text("--- a/app.py\n+++ b/app.py\n@@ -0,0 +1 @@\n+x = 1\n")
    seen = {}

    class _Collector:
        review_paths = ("app.py",)

        def prepare(self, diff_text):
            seen["context_diff"] = diff_text
            return [SimpleNamespace(grounding=SimpleNamespace(text="source context"))]

    def fake_audit(*args, **kwargs):
        options = kwargs["options"]
        seen["context"] = options.grounding.prepare_diff(diff.read_text())[0].grounding.text
        seen["verification_root"] = options.verification.root
        seen["verifier"] = options.verification.verifier
        seen["verification_confirmers"] = options.verification.confirmers
        seen["verification_found_by"] = options.verification.found_by
        seen["verification_concurrency"] = options.verification.concurrency
        return SimpleNamespace(outcome=SimpleNamespace(findings=[], failures=[], degraded=False))

    def fake_context_collector(root, profile, *, review_diff=""):
        seen["review_diff"] = review_diff
        return _Collector()

    monkeypatch.setattr(climod, "build_diff_context_collector", fake_context_collector)
    monkeypatch.setattr(
        climod,
        "_build_diff_providers",
        lambda args: climod.DiffProviders(base_provider=MockProvider(default="{}"), base_model="mock"),
    )
    monkeypatch.setattr(climod, "run_diff_review", fake_audit)

    assert main(["review", "diff", "--file", str(diff), "--repository", str(repo), "--api-key", "k"]) == 0
    assert seen["context"] == "source context"
    assert seen["review_diff"] == diff.read_text()
    assert seen["verification_root"] == str(repo)
    assert seen["verifier"] is not None
    assert seen["verification_confirmers"] == []
    assert seen["verification_found_by"] == ("claude-opus-5",)
    assert seen["verification_concurrency"] == 8


def test_review_diff_standard_uses_distinct_judge_and_finder_confirmers(monkeypatch, tmp_path):
    """A standard diff finder cannot also approve deleting its own finding."""
    repo = tmp_path / "repo"
    repo.mkdir()
    diff = tmp_path / "c.diff"
    diff.write_text("--- a/app.py\n+++ b/app.py\n@@ -0,0 +1 @@\n+x = 1\n")
    seen = {}

    def fake_audit(*args, **kwargs):
        verification = kwargs["options"].verification
        seen["verification_confirmers"] = verification.confirmers
        seen["verification_found_by"] = verification.found_by
        seen["verification_concurrency"] = verification.concurrency
        return SimpleNamespace(outcome=SimpleNamespace(findings=[], failures=[], degraded=False))

    monkeypatch.setattr(
        climod,
        "_build_diff_providers",
        lambda args: climod.DiffProviders(base_provider=MockProvider(default="{}"), base_model="finder"),
    )
    monkeypatch.setattr(climod, "_role_provider", lambda *args, **kwargs: MockProvider(default="{}"))
    monkeypatch.setattr(climod, "run_diff_review", fake_audit)

    assert (
        main(
            [
                "review",
                "diff",
                "--file",
                str(diff),
                "--repository",
                str(repo),
                "--api-key",
                "k",
                "--finder-model",
                "finder",
                "--challenger-model",
                "skeptic",
                "--judge-model",
                "judge",
                "--concurrency",
                "4",
            ]
        )
        == 0
    )
    assert [label for label, _checker in seen["verification_confirmers"]] == ["judge", "finder"]
    assert seen["verification_found_by"] == ("finder",)
    assert seen["verification_concurrency"] == 4


def test_review_diff_adversarial_uses_finder_as_a_provenance_aware_confirmer(monkeypatch, tmp_path):
    """Adversarial provenance lets the finder confirm only findings it did not surface."""
    repo = tmp_path / "repo"
    repo.mkdir()
    diff = tmp_path / "c.diff"
    diff.write_text("--- a/app.py\n+++ b/app.py\n@@ -0,0 +1 @@\n+x = 1\n")
    seen = {}

    def fake_audit(*args, **kwargs):
        verification = kwargs["options"].verification
        seen["verification_confirmers"] = verification.confirmers
        seen["verification_found_by"] = verification.found_by
        return SimpleNamespace(outcome=SimpleNamespace(findings=[], failures=[], degraded=False))

    monkeypatch.setattr(
        climod,
        "_build_diff_providers",
        lambda args: climod.DiffProviders(
            base_provider=MockProvider(default="{}"),
            base_model="finder",
            finder_provider=MockProvider(default="{}"),
            finder_model="finder",
            challenger_provider=MockProvider(default="{}"),
            challenger_model="skeptic",
            judge_provider=MockProvider(default="{}"),
            judge_model="judge",
        ),
    )
    monkeypatch.setattr(climod, "_role_provider", lambda *args, **kwargs: MockProvider(default="{}"))
    monkeypatch.setattr(climod, "run_diff_review", fake_audit)

    assert (
        main(
            [
                "review",
                "diff",
                "--file",
                str(diff),
                "--repository",
                str(repo),
                "--mode",
                "adversarial",
                "--api-key",
                "k",
                "--finder-model",
                "finder",
                "--challenger-model",
                "skeptic",
                "--judge-model",
                "judge",
            ]
        )
        == 0
    )
    assert [label for label, _checker in seen["verification_confirmers"]] == ["judge", "finder"]
    assert seen["verification_found_by"] == ()


def test_review_diff_bad_file_exits_nonzero(capsys):
    rc = main(["review", "diff", "--file", "/nonexistent/nope.diff"])
    assert rc == 1
    assert "failed" in capsys.readouterr().err


def test_review_diff_empty_stdin_is_clean(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    monkeypatch.setattr(
        "cyberjury.providers.configuration.make_provider",
        lambda *a, **k: MockProvider(default='{"findings": []}'),
    )
    rc = main(["review", "diff", "--api-key", "x"])
    assert rc == 0
    assert "no findings" in capsys.readouterr().out.lower()


def test_diff_adversarial_rounds_flow_into_audit(monkeypatch):
    captured = {}

    def fake_audit(diff, *, options, **kw):
        captured["mode"] = options.roles.mode
        captured["max_rounds"] = options.roles.max_rounds
        return SimpleNamespace(outcome=SimpleNamespace(findings=[], failures=[], degraded=False))

    monkeypatch.setattr(climod, "run_diff_review", fake_audit)
    monkeypatch.setattr("sys.stdin", io.StringIO(_DIFF))
    assert main(["review", "diff", "--mode", "adversarial", "--rounds", "5", "--api-key", "k"]) == 0
    assert captured == {"mode": "adversarial", "max_rounds": 5}


def test_diff_degraded_audit_exits_nonzero_and_surfaces_the_error(monkeypatch, capsys):
    monkeypatch.setattr(
        climod,
        "run_diff_review",
        lambda *a, **k: SimpleNamespace(outcome=SimpleNamespace(findings=[], failures=[], degraded=True)),
    )
    monkeypatch.setattr("sys.stdin", io.StringIO(_DIFF))
    rc = main(["review", "diff", "--mode", "adversarial", "--api-key", "k"])
    assert rc == 1
    assert "degraded" in capsys.readouterr().err


def test_diff_degraded_audit_surfaces_failed_batch_details(monkeypatch, capsys):
    """Large diff failures include batch paths before the generic degraded error."""

    def fake_audit(*args, **kwargs):
        return SimpleNamespace(
            outcome=SimpleNamespace(
                findings=[],
                degraded=True,
                failures=[
                    ReviewUnitFailure(
                        index=2,
                        total=3,
                        paths=("app.py", "billing.py", "routes.py", "views.py"),
                        reason="AuditError: blocked",
                    )
                ],
            )
        )

    monkeypatch.setattr(climod, "run_diff_review", fake_audit)
    rc = main(["review", "diff", "--dry-run"])

    err = capsys.readouterr().err
    assert rc == 1
    assert "diff batch 2/3 failed for app.py, billing.py, routes.py, and 1 more: AuditError: blocked" in err
    assert "the diff audit degraded" in err
