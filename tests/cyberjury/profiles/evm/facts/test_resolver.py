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


def test_single_file_review_keeps_exact_internal_dependencies(tmp_path):
    from cyberjury.profiles.evm.facts.analyzer import AnalyzedCall, AnalyzedContract, AnalyzedProject
    from cyberjury.profiles.evm.facts.resolver import load_profile_detection, resolve_project

    source = tmp_path / "Vault.sol"
    text = "contract Vault { function f() public { g(); } function g() internal {} }"
    source.write_text(text)
    f_start = text.index("function f")
    g_start = text.index("function g")
    g = _analyzed_function(
        key=2,
        name="g()",
        source=_analyzed_source(absolute=str(source), start=g_start, length=len(text) - g_start - 2),
    )
    f = _analyzed_function(
        key=1,
        name="f()",
        source=_analyzed_source(absolute=str(source), start=f_start, length=g_start - f_start - 1),
        calls=(AnalyzedCall(target_key=2, target_name="g()"),),
    )
    analyzed = AnalyzedProject(
        contracts=(
            AnalyzedContract(
                identity="Vault.sol::Vault",
                name="Vault",
                is_interface=False,
                source=_analyzed_source(absolute=str(source), start=0, length=len(text)),
                state=(),
                functions=(f, g),
                key=10,
            ),
        )
    )

    resolved = resolve_project(analyzed, source, load_profile_detection())

    assert [(edge.source.file, edge.target.file, edge.target.name) for edge in resolved.call_candidates] == [
        ("Vault.sol", "Vault.sol", "g()")
    ]


def test_missing_function_range_is_always_a_source_limitation(tmp_path):
    from cyberjury.profiles.evm.facts.analyzer import AnalyzedContract, AnalyzedProject
    from cyberjury.profiles.evm.facts.resolver import load_profile_detection, resolve_project

    source = tmp_path / "Vault.sol"
    text = "contract Vault { function withdraw() external {} }"
    source.write_text(text)
    analyzed = AnalyzedProject(
        contracts=(
            AnalyzedContract(
                identity="Vault.sol::Vault",
                name="Vault",
                is_interface=False,
                source=_analyzed_source(absolute=str(source), start=0, length=len(text)),
                state=(),
                functions=(_analyzed_function(name="withdraw()", source=_analyzed_source(absolute=str(source))),),
                key=10,
            ),
        )
    )

    resolved = resolve_project(analyzed, tmp_path, load_profile_detection())

    assert any("source range for function withdraw()" in item.reason for item in resolved.limitations)


def test_modifiers_and_inheritance_become_exact_definition_edges(tmp_path):
    from cyberjury.profiles.evm.facts.analyzer import (
        AnalyzedBaseReference,
        AnalyzedCall,
        AnalyzedContract,
        AnalyzedProject,
    )
    from cyberjury.profiles.evm.facts.resolver import load_profile_detection, resolve_project

    source = tmp_path / "Vault.sol"
    text = "contract Base { modifier onlyOwner() { _; } } contract Vault is Base { function f() public {} }"
    source.write_text(text)
    modifier_start = text.index("modifier")
    child_start = text.index("contract Vault")
    function_start = text.index("function f")
    modifier = _analyzed_function(
        key=1,
        name="onlyOwner()",
        source=_analyzed_source(absolute=str(source), start=modifier_start, length=28),
    )
    function = _analyzed_function(
        key=2,
        name="f()",
        source=_analyzed_source(absolute=str(source), start=function_start, length=22),
        calls=(AnalyzedCall(target_key=1, target_name="onlyOwner()"),),
    )
    analyzed = AnalyzedProject(
        contracts=(
            AnalyzedContract(
                identity="Vault.sol::Base",
                name="Base",
                is_interface=False,
                source=_analyzed_source(absolute=str(source), start=0, length=child_start - 1),
                state=(),
                functions=(modifier,),
                key=10,
            ),
            AnalyzedContract(
                identity="Vault.sol::Vault",
                name="Vault",
                is_interface=False,
                source=_analyzed_source(absolute=str(source), start=child_start, length=len(text) - child_start),
                state=(),
                functions=(function,),
                key=20,
                bases=(AnalyzedBaseReference(target_key=10, target_name="Base"),),
            ),
        )
    )

    resolved = resolve_project(analyzed, tmp_path, load_profile_detection())

    assert {(edge.reference, edge.target.name) for edge in resolved.call_candidates} == {
        ("onlyOwner()", "onlyOwner()"),
    }
    assert {(edge.kind, edge.reference, edge.target.name) for edge in resolved.structural_candidates} == {
        ("inheritance", "Base", "Base"),
    }
