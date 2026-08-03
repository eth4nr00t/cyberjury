---
id: resource-exhaustion
title: Uncontrolled Resource Consumption
lens: resource-exhaustion
impact: HIGH
tags: [cwe-400, cwe-1333, cwe-770, owasp-a04]
triggers: ["re.compile", "re.match", "re.search", "new RegExp", ".match(", "extractall", "decompress", "zipfile", "gzip", "read()", "* int", "range(int", "json.loads", "while"]
---

# Uncontrolled Resource Consumption

A single request, or a few, exhausts a server resource and takes the service down. The
common forms are a catastrophic-backtracking regular expression run on attacker input, the
ReDoS shape, an allocation or a loop sized by an attacker-controlled number with no cap, and
a decompression or parse step that expands attacker input without a bound, the zip or JSON
bomb. Bound the work before doing it: cap the input size, reject or limit the count before
allocating, run untrusted patterns on a linear-time engine or a fixed timeout, and limit the
decompressed size.

## Python
Vulnerable:
```python
# catastrophic backtracking, a crafted input hangs the worker
if re.match(r"^(\w+\s?)*$", request.args["q"]):
    accept()
```
Secure:
```python
if len(request.args["q"]) <= 256 and re.match(r"^\w[\w ]{0,255}$", request.args["q"]):
    accept()
```

A second common shape is an allocation sized from input, such as `b"\x00" * int(request.args["n"])`
or a loop over a client-supplied count, with no upper bound. Validate the bound before the
allocation. For an upload or an archive, cap the declared and the decompressed size and stop
reading past the limit.

## Not a Finding

Report this only when one or a few requests cause a real outage: a worker hang, a process
crash, or memory or CPU exhaustion that denies service. A bounded loop, a fixed-size
allocation, a regex with no ambiguous repetition, or input that comes from trusted server
config is not a finding. Mere slowness, a missing rate limit, or work bounded by an existing
size or count check is hardening advice, not an exploitable finding. A pattern or size that
an attacker cannot influence is not reportable.
