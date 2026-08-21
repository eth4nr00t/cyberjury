---
id: python
title: Python
kind: language
detect:
  files: ["*.py"]
entrypoint_files: ["*__main__.py", "*main.py", "*cli.py", "*/cli/*.py", "*/commands/*.py"]
entrypoint_markers: ["argparse", "ArgumentParser", "click.command", "click.group", "@click.command", "@click.group"]
logic_layer_files: ["*/services/*.py", "*services.py", "*/managers/*.py", "*managers.py", "*/dao/*.py", "*dao.py", "*/repositories/*.py", "*/repository/*.py"]
public_api_patterns: ["^def [a-z]", "^async def [a-z]", "^class [A-Z]"]
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
