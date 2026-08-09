---
id: code-injection
title: Code Injection
impact: CRITICAL
tags: [cwe-94, owasp-a03, injection, rce]
selection_hints: ["eval(", "exec(", "new Function", "setTimeout(\"", "setInterval(\"", "vm.runInContext", "vm.runInNewContext", "runInThisContext"]
---

# Code Injection

Passing untrusted input to a language evaluation primitive such as eval, exec, compile, dynamic import, or JS Function lets an attacker execute arbitrary code. Never evaluate untrusted input. Parse it with a data-only parser or dispatch through an allowlist.

## Python
Vulnerable:
```python
result = eval(request.args["expr"])
exec(user_supplied_code)
```
Secure:
```python
import ast

result = ast.literal_eval(request.args["expr"])
```
