---
id: python
title: Python
kind: language
detect:
  files: ["*.py"]
entrypoint_files: ["*__main__.py", "*main.py", "*cli.py", "*/cli/*.py", "*/commands/*.py"]
entrypoint_markers: ["argparse", "ArgumentParser", "click.command", "click.group", "@click.command", "@click.group"]
logic_layers: ["*/services/*.py", "*services.py", "*/managers/*.py", "*managers.py", "*/dao/*.py", "*dao.py", "*/repositories/*.py", "*/repository/*.py"]
api_patterns: ["^def [a-z]", "^class [A-Z]"]
---
# Python Review Notes

Where untrusted input enters beyond web routes, which the framework guides cover:
CLI such as `argparse` or `click`, scheduled jobs, queue consumers, and any function
fed an external value. Non-HTTP sources matter as much as routes.

## Common Sinks
- Code execution: `eval`, `exec`, `subprocess(..., shell=True)`, `os.system`.
- Deserialization: `pickle.loads`, `yaml.load` without `SafeLoader`, `marshal`.
- SQL: a string-built query handed to a DB cursor or ORM `.raw()`/`.extra()`.
- XML/XXE: `lxml`/`xml.etree` parsing attacker XML.
- Path: `open()` / `os.path.join` on a path built from user input.
- SSRF: `requests.get(user_url)` and similar, a fetch of a URL from input.
- Template: rendering user input through a template engine.

## Gotchas
- A secret compared with `==` instead of `hmac.compare_digest` leaks via timing.
- A bare `except:` around an auth or validation call swallows the failure, so the
  code proceeds as if it passed.
- `assert` used for an authorization check is stripped under `python -O`, so the
  check vanishes in production.
