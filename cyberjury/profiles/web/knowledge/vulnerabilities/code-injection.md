---
id: code-injection
title: Code Injection
impact: CRITICAL
tags: [cwe-94, owasp-a03, injection, rce]
selection_hints: ["eval(", "exec(", "new Function", "setTimeout(\"", "setInterval(\"", "vm.runInContext", "vm.runInNewContext", "runInThisContext"]
---

# Code Injection

## Security Condition

Passing attacker controlled text to a language evaluation primitive such as `eval`, `exec`, or the
JavaScript `Function` constructor lets the attacker execute code with the application's permissions.
The missing control is a data parser or closed operation allowlist before the evaluation sink.

## Review Guidance

Report the call to the evaluation primitive when a request, message, stored attacker value, or file
content can reach its code argument. Never evaluate untrusted text.

## Examples

### Dynamic Code Evaluation

Vulnerable:

```python
def calculate(expression):
    return eval(expression)
```

Secure:

```python
OPERATIONS = {
    "add": lambda left, right: left + right,
    "subtract": lambda left, right: left - right,
}


def calculate(operation, left, right):
    selected = OPERATIONS.get(operation)
    if selected is None:
        raise ValueError("unknown operation")
    return selected(left, right)
```

## Not a Finding

Evaluation of a constant string is not attacker controlled. Parsing untrusted input with a
data-only parser is not code injection, and dispatch through a closed mapping of names to fixed
callables is safe when the attacker cannot add or replace entries. Input validation does not make
an evaluation sink safe when accepted text can still express executable syntax.
