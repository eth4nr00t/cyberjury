"""CLI provider seats inherit defaults without leaking vendor specific settings."""

import io
from types import SimpleNamespace

import pytest

import cyberjury.cli as climod
from cyberjury.cli import main

_FILE_A = "diff --git a/a.py b/a.py\n@@ -0,0 +1 @@\n+x = 1\n"

_DIFF = _FILE_A


def test_diff_without_key_errors_loud(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr("sys.stdin", io.StringIO(_DIFF))
    with pytest.raises(SystemExit, match="no reachable API key"):
        main(["review", "diff"])


def test_diff_openai_without_key_errors_loud(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr("sys.stdin", io.StringIO(_DIFF))
    with pytest.raises(SystemExit, match="no reachable API key"):
        main(["review", "diff", "--provider", "openai"])


def test_diff_adversarial_resolves_each_seat_independently(monkeypatch):
    captured = {}

    def fake_audit(diff, *, options, **kw):
        captured.update(
            finder=options.roles.finder_provider,
            challenger=options.roles.challenger_provider,
            judge=options.roles.judge_provider,
        )
        return SimpleNamespace(outcome=SimpleNamespace(findings=[], failures=[], degraded=False))

    monkeypatch.setattr(climod, "run_diff_review", fake_audit)
    monkeypatch.setattr("sys.stdin", io.StringIO(_DIFF))
    rc = main(
        [
            "review",
            "diff",
            "--mode",
            "adversarial",
            "--api-key",
            "k",
            "--challenger-provider",
            "openai",
            "--challenger-api-key",
            "k2",
        ]
    )
    assert rc == 0
    assert captured["finder"] is not captured["challenger"]
    assert captured["judge"] is not captured["challenger"]


def test_diff_standard_uses_the_finder_seat_when_it_is_overridden(monkeypatch):
    """The single pass must honor finder-specific backend overrides."""
    from argparse import Namespace

    captured = {}

    def fake_create(configuration, mode):
        captured["configuration"] = configuration
        captured["mode"] = mode
        return climod.DiffProviders(
            base_provider=object(),
            base_model=configuration.finder.model,
            finder_provider=object(),
            finder_model=configuration.finder.model,
        )

    monkeypatch.setattr(climod, "create_diff_providers", fake_create)
    args = Namespace(
        provider="anthropic",
        model="base",
        api_key="k",
        api_base=None,
        wire_api="chat",
        finder_provider=None,
        finder_model="finder",
        finder_api_key=None,
        finder_api_base=None,
        finder_wire_api=None,
        challenger_provider=None,
        challenger_model=None,
        challenger_api_key=None,
        challenger_api_base=None,
        challenger_wire_api=None,
        judge_provider=None,
        judge_model=None,
        judge_api_key=None,
        judge_api_base=None,
        judge_wire_api=None,
        mode="standard",
        retries=0,
        timeout=10,
    )

    providers = climod._build_diff_providers(args)

    assert providers.base_model == "finder"
    assert providers.finder_model == "finder"
    assert providers.challenger_provider is None
    assert providers.judge_provider is None
    assert captured["configuration"].finder.model == "finder"
    assert captured["mode"] == "standard"


def _role_args(**over):
    from argparse import Namespace

    base = {"provider": "anthropic", "model": "claude-base", "api_key": "basekey", "api_base": None, "wire_api": "chat"}
    for role in ("finder", "challenger", "judge"):
        for field in ("provider", "model", "api_key", "api_base", "wire_api"):
            base[f"{role}_{field}"] = None
    base.update(over)
    return Namespace(**base)


def test_role_spec_inherits_base_when_unset():
    from cyberjury.cli import _base_spec, _role_spec

    a = _role_args()
    s = _role_spec(a, "challenger", _base_spec(a))
    assert (s.provider, s.model, s.api_key) == ("anthropic", "claude-base", "basekey")


def test_base_seat_wire_flows_and_role_inherits_it():
    from cyberjury.cli import _base_spec, _role_spec

    a = _role_args(wire_api="responses")
    base = _base_spec(a)
    assert base.wire_api == "responses"
    assert _role_spec(a, "challenger", base).wire_api == "responses"


def test_role_spec_cross_vendor_override_drops_base_provider_specific_fields():
    """A provider switch must not carry vendor-specific base settings into the role."""
    from cyberjury.cli import _base_spec, _role_spec

    a = _role_args(
        api_base="https://anthropic.example.test",
        wire_api="chat",
        challenger_provider="openai",
    )
    s = _role_spec(a, "challenger", _base_spec(a))
    assert (s.provider, s.model) == ("openai", "gpt-5.6")
    assert s.api_key is None
    assert s.api_base is None
    assert s.wire_api is None


def test_role_spec_cross_vendor_keeps_explicit_role_fields():
    """Role fields stay authoritative when the role intentionally changes provider."""
    from cyberjury.cli import _base_spec, _role_spec
    from cyberjury.providers.configuration import ProviderSeat

    a = _role_args(
        challenger_provider="openai",
        challenger_model="gpt-x",
        challenger_api_key="role-key",
        challenger_api_base="https://openai.example.test",
        challenger_wire_api="responses",
    )
    s = _role_spec(a, "challenger", _base_spec(a))
    assert s == ProviderSeat(
        provider="openai",
        model="gpt-x",
        api_key="role-key",
        api_base="https://openai.example.test",
        wire_api="responses",
    )


def test_role_spec_same_vendor_override_keeps_base_key():
    from cyberjury.cli import _base_spec, _role_spec

    a = _role_args(challenger_model="claude-other")
    s = _role_spec(a, "challenger", _base_spec(a))
    assert (s.provider, s.model, s.api_key) == ("anthropic", "claude-other", "basekey")


def test_confirmers_exclude_the_skeptic_and_dedupe(monkeypatch):
    from argparse import Namespace

    from cyberjury.cli import _confirmers
    from cyberjury.providers.configuration import ProviderSeat

    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    a = Namespace(retries=0, timeout=10)
    chal = ProviderSeat(provider="anthropic", model="skep", api_key="k", wire_api="chat")
    jud = ProviderSeat(provider="anthropic", model="judge", api_key="k", wire_api="chat")
    fnd = ProviderSeat(provider="anthropic", model="judge", api_key="k", wire_api="chat")
    confirmers = _confirmers(a, challenger=chal, judge=jud, finder=fnd)
    assert [label for label, _ in confirmers] == ["judge"]
    same = ProviderSeat(provider="anthropic", model="skep", api_key="k", wire_api="chat")
    assert _confirmers(a, challenger=chal, judge=same, finder=same) == []


def test_key_reachable_by_explicit_key_or_vendor_env(monkeypatch):
    from cyberjury.cli import _key_reachable
    from cyberjury.providers.configuration import ProviderSeat

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert _key_reachable(ProviderSeat(provider="anthropic", model="m", api_key="k"))
    assert not _key_reachable(ProviderSeat(provider="anthropic", model="m"))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "env-key")
    assert _key_reachable(ProviderSeat(provider="anthropic", model="m"))
    assert not _key_reachable(ProviderSeat(provider="openai", model="m"))


def test_require_key_errors_loud_at_startup_on_a_missing_key(monkeypatch):
    from cyberjury.cli import _require_key
    from cyberjury.providers.configuration import ProviderSeat

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(SystemExit, match="no reachable API key"):
        _require_key(ProviderSeat(provider="openai", model="m"))
    _require_key(ProviderSeat(provider="anthropic", model="m", api_key="k"))


def test_note_verify_route_states_the_active_route(capsys):
    from argparse import Namespace

    from cyberjury.cli import _note_verify_route

    args = Namespace(verify=True, dry_run=False)
    _note_verify_route(args, [("m1", object()), ("m2", object())])
    out = capsys.readouterr().err
    assert "skeptic plus 2 confirmers" in out
    _note_verify_route(args, [("m1", object())])
    assert "skeptic plus 1 confirmer," in capsys.readouterr().err
    _note_verify_route(args, [])
    assert "keep-all" in capsys.readouterr().err
    _note_verify_route(Namespace(verify=True, dry_run=True), [])
    assert "Verify route" not in capsys.readouterr().err
