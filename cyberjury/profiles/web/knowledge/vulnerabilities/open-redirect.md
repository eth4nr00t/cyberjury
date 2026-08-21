---
id: open-redirect
title: Open Redirect
impact: MEDIUM
tags: [cwe-601, owasp-a01]
selection_hints: ["redirect(", "redirect_to", "next=", "return_url", "redirect_uri", "continue=", "callback_url", "sendRedirect", "res.redirect", "response.redirect"]
---

# Open Redirect

## Security Condition

A redirect target taken from untrusted input without validation lets an attacker send victims to an
attacker controlled site for phishing. In an authorization flow it can also deliver a code or token
to an attacker controlled redirect target.

## Review Guidance

Report the redirect call where request or stored attacker input controls the destination. Use a
fixed allowlist of complete destinations or local paths.

## Examples

### Redirect Destination Policy

Vulnerable:

```python
from flask import redirect, request


def continue_login():
    return redirect(request.args["next"])
```

Secure:

```python
from flask import redirect, request

ALLOWED_PATHS = {"/account", "/dashboard"}


def continue_login():
    target = request.args.get("next", "/dashboard")
    if target not in ALLOWED_PATHS:
        target = "/dashboard"
    return redirect(target)
```

## Not a Finding

A redirect is safe when its destination is a constant, selected by an opaque server side key, or
matched by exact equality against a fixed allowlist. A relative path check must reject network
path references, backslashes, encoded separators, and parser ambiguities. Do not report a redirect
to attacker controlled content on the same trusted origin unless the redirect crosses a security
boundary or enables a concrete exploit.
