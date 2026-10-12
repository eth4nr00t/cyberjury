---
id: python
title: Python
kind: language
detect:
  files: ["*.py"]
entrypoint_globs: ["*__main__.py", "*main.py", "*cli.py", "*/cli/*.py", "*/commands/*.py"]
entrypoint_markers: ["argparse", "ArgumentParser", "click.command", "click.group", "@click.command", "@click.group"]
logic_layer_globs: ["*/services/*.py", "*services.py", "*/managers/*.py", "*managers.py", "*/dao/*.py", "*dao.py", "*/repositories/*.py", "*/repository/*.py"]
exported_symbol_patterns: ["^def [a-z]", "^async def [a-z]", "^class [A-Z]"]
---

# Python Review Notes

## Attack Surface

This guide covers untrusted input beyond the web routes described by the framework guides. Sources
include a CLI such as `argparse` or `click`, scheduled jobs, queue consumers, and any function fed
an external value. Non-HTTP sources matter as much as routes.

## Trust Boundaries

Python does not provide an application authorization boundary. CLI, queue, job, and web values
remain untrusted until framework or application code binds them to an authenticated actor, tenant,
resource, and current operation.

## Review Guidance

### Common Sinks

- Code execution: `eval`, `exec`, `subprocess(..., shell=True)`, `os.system`.
- Deserialization: `pickle.loads`, `yaml.load` without `SafeLoader`, `marshal`.
- SQL: a string-built query handed to a DB cursor or ORM `.raw()`/`.extra()`.
- XML external entities: an XML parser configured to resolve external entities while parsing
  attacker XML. Standard `xml.etree.ElementTree` does not resolve external entities
  by default, so its mere use is not `xml-external-entity`.
- Path: `open()` / `os.path.join` on a path built from user input.
- Generated filenames: a user-configurable template or stored path segment remains attacker controlled when it
  reaches filename generation or `os.path.join`; require resolved containment under the trusted storage root.
- The generic flow `model path field -> filename generator -> object.source_path -> open/rename` is a concrete
  filesystem effect when no resolved containment check intervenes.
- Removing leading or trailing separators does not contain `..` path components. Follow the generated filename
  through the final resolved filesystem operation before treating a storage root as protected. A downstream
  `open`, rename, move, or directory creation is the concrete filesystem effect. Source evidence is enough;
  a runtime PoC is not required to establish missing containment.
- For a diff location, anchor the finding at the changed renderer or validator that accepts the escaping value,
  or at the final filesystem sink when the sink omits containment. A helper that only forwards the generated
  path is supporting evidence, not the primary vulnerability location.
- SSRF: `requests.get(user_url)` and similar, a fetch of a URL from input.
- Template: rendering user input through a template engine.

### Gotchas

- A secret compared with `==` instead of `hmac.compare_digest` leaks via timing.
- A bare `except:` around an auth or validation call swallows the failure, so the
  code proceeds as if it passed.
- `assert` used for an authorization check is stripped under `python -O`, so the
  check vanishes in production.
- Deserialization and parsing primitives are not findings by name alone. Confirm
  attacker control, the unsafe parser mode, and a concrete dangerous operation or
  resource impact before reporting.

## Safe Boundaries

Python code is bounded when authorization failures stop execution, checks survive runtime
optimization, object access uses verified scope, and code, parser, query, path, network, and
template operations apply the control required by their concrete input.
