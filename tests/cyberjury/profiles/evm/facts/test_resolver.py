"""EVM resolution converts byte ranges and exact call endpoints at one boundary."""


def _analyzed_source(*, absolute="", short="", used="", start=None, length=None):
    from cyberjury.profiles.evm.facts.analyzer import AnalyzedSource

    return AnalyzedSource(absolute=absolute, short=short, used=used, start=start, length=length)


def _analyzed_function(*, key=1, name="function()", source=None, calls=()):
    from cyberjury.profiles.evm.facts.analyzer import AnalyzedFunction

    return AnalyzedFunction(
        key=key,
        name=name,
        visibility="internal",
        modifiers=(),
        reads=(),
        writes=(),
        calls=calls,
        external_call=False,
        sends_eth=False,
        can_reenter=False,
        source=source or _analyzed_source(),
    )


def test_slither_ranges_slice_normalized_utf8_and_crlf_source(tmp_path):
    from cyberjury.profiles.evm.facts.resolver import function_range
    from cyberjury.review.context import definition_evidence
    from cyberjury.review.facts import DefinitionFragment, DefinitionUnitPlan

    raw_prefix = "// café\r\ncontract Vault {\r\n    "
    raw_body = "function withdraw() external {\r\n        transfer();\r\n    }"
    source = f"{raw_prefix}{raw_body}\r\n}}\r\n"
    path = tmp_path / "Vault.sol"
    path.write_bytes(source.encode("utf-8"))
    start = len(raw_prefix.encode("utf-8"))
    length = len(raw_body.encode("utf-8"))
    function = _analyzed_function(source=_analyzed_source(absolute=str(path), start=start, length=length))

    span = function_range(function, {})
    fragment = DefinitionFragment("Vault.sol", "withdraw()", span[0], span[1])
    plan = DefinitionUnitPlan(seeds=(fragment,))
    evidence = definition_evidence(tmp_path, plan, include_seeds=True)

    assert len(evidence) == 1
    assert "function withdraw() external" in evidence[0].text
    assert "transfer();" in evidence[0].text
    assert "}" in evidence[0].text


def test_rel_file_relativizes_to_root_and_falls_back(tmp_path):
    from cyberjury.profiles.evm.facts.resolver import relative_file

    root = tmp_path.resolve()
    assert relative_file(_analyzed_source(absolute=str(root / "src" / "Vault.sol")), root) == "src/Vault.sol"
    assert relative_file(_analyzed_source(absolute="/elsewhere/Ownable.sol"), root) == "Ownable.sol"
    assert relative_file(_analyzed_source(absolute=str(root / "Vault.sol")), root / "Vault.sol") == "Vault.sol"
    assert relative_file(_analyzed_source(), root) == ""
