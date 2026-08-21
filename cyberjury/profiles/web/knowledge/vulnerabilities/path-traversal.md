---
id: path-traversal
title: Path Traversal
impact: HIGH
tags: [cwe-22, owasp-a01]
selection_hints: ["os.path.join", "path.join", "filepath.Join", "send_file", "send_from_directory", "sendfile", "readFile", "createReadStream", "safe_join", "../", "..\\\\", "path.resolve("]
---

# Path Traversal

## Security Condition

A filesystem path built from untrusted input without containment lets `../`, an absolute path, or an
encoded separator escape the intended directory. The resulting read, write, delete, extract, or send
operation can expose secrets or overwrite executable data.

## Review Guidance

Report the file operation where the attacker controlled segment reaches the filesystem, together
with the missing containment decision. Resolve the path and confirm it stays within a fixed base, or
map an opaque identifier to a server selected path.

## Examples

### Canonical Filesystem Confinement

Vulnerable:

```python
from pathlib import Path


def read_document(base: Path, name: str) -> bytes:
    return (base / name).read_bytes()
```

Secure:

```python
from pathlib import Path


def read_document(base: Path, name: str) -> bytes:
    trusted_base = base.resolve()
    target = (trusted_base / name).resolve()
    if not target.is_relative_to(trusted_base):
        raise ValueError("path escapes base directory")
    return target.read_bytes()
```

## Not a Finding

There is no traversal when the input is contained before the file operation, whichever way the
containment is done:

- only a platform aware basename is used after alternate separators and absolute path forms are
  rejected, and the application does not need attacker selected subdirectories,
- the resolved path is confirmed to stay within a fixed base, whether by an explicit
  containment check such as `is_relative_to` or `realpath` under base, or by a framework helper that
  does the same and rejects `..` and absolute paths, such as Flask `send_from_directory` or
  Werkzeug `safe_join`,
- the value is from an allowlist, or is a constant or trusted config path.

This holds as long as the base directory itself is not attacker-controlled. For example
`open(os.path.join(BASE, os.path.basename(name)))` and `send_from_directory(BASE, name)` are
both safe. Report only when a user-controlled segment can still escape the base.
