---
id: path-traversal
title: Path Traversal
lens: path-traversal
impact: HIGH
tags: [cwe-22, owasp-a01]
triggers: ["open(", "os.path.join", "send_file", "sendfile", "readFile", "filename", "../", "upload"]
---

# Path Traversal

A filesystem path built from untrusted input without containment lets `../` escape the intended directory. Resolve the path and confirm it stays within an allowed base, or use only the basename.

## Python
Vulnerable:
```python
open(os.path.join(UPLOAD_DIR, request.args["filename"]))
```
Secure:
```python
base = UPLOAD_DIR.resolve()
target = (base / filename).resolve()
if not target.is_relative_to(base):
    raise ValueError("path escapes base dir")
```

## Not a Finding

There is no traversal when the input is contained before the file operation, whichever way the
containment is done:
- only the basename is used, stripping `../` and any directory parts,
- the resolved path is confirmed to stay within a fixed base, whether by an explicit
  containment check such as `is_relative_to` or `realpath` under base, or by a framework helper that
  does the same and rejects `..` and absolute paths, such as Flask `send_from_directory` or
  Werkzeug `safe_join`,
- the value is from an allowlist, or is a constant / trusted-config path.

This holds as long as the base directory itself is not attacker-controlled. For example
`open(os.path.join(BASE, os.path.basename(name)))` and `send_from_directory(BASE, name)` are
both safe. Report only when a user-controlled segment can still escape the base.
