---
id: code-injection
title: Code Injection
impact: CRITICAL
tags: [cwe-94, owasp-a03, injection, rce]
selection_hints: ["eval(", "exec(", "new Function", "setTimeout(\"", "setInterval(\"", "vm.runInContext", "vm.runInNewContext", "runInThisContext"]
---

# Code Injection

Passing attacker controlled text to a language evaluation primitive such as `eval`, `exec`, or
the JavaScript `Function` constructor lets the attacker execute code with the application's
permissions. The missing control is a data parser or closed operation allowlist before the
evaluation sink. Report the call to the evaluation primitive when a request, message, stored
attacker value, or file content can reach its code argument. Never evaluate untrusted text.

## Python

Vulnerable:

```python
def calculate(expression):
    return eval(expression)
```

Secure:

```python
import json


def read_number(encoded):
    value = json.loads(encoded)
    if not isinstance(value, int | float):
        raise ValueError("number required")
    return value
```

## JavaScript

Vulnerable:

```javascript
function calculate(expression) {
  return Function(`return (${expression})`)()
}
```

Secure:

```javascript
const operations = {
  add: (left, right) => left + right,
  subtract: (left, right) => left - right,
}

function calculate(operation, left, right) {
  const selected = operations[operation]
  if (!selected) throw new Error("unknown operation")
  return selected(left, right)
}
```

## Not a Finding

Evaluation of a constant string is not attacker controlled. Parsing untrusted input with a
data-only parser is not code injection, and dispatch through a closed mapping of names to fixed
callables is safe when the attacker cannot add or replace entries. Input validation does not make
an evaluation sink safe when accepted text can still express executable syntax.
