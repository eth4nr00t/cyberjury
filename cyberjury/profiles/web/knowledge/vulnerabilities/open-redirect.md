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

An allowlist is not sufficient when its comparison treats distinct destinations as equivalent.
Complete redirect URIs need exact matching unless the protocol defines a component specific
comparison. Whole URI case folding is unsafe because path and query components can be case
sensitive even when the scheme and host are not.

## Review Guidance

Report the redirect call or shared validation boundary where request or stored attacker input can
select a destination outside the intended policy. Trace normalization before comparison. Use exact
matching for complete registered redirect URIs, or compare parsed components according to the
protocol while preserving the semantics of case sensitive components. Local path policies must
also reject network path references and parser ambiguities.

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

### Redirect Allowlist Equivalence

Vulnerable:

```python
REGISTERED_REDIRECTS = {"https://client.example/Callback"}


def is_registered_redirect(target):
    folded = {redirect.casefold() for redirect in REGISTERED_REDIRECTS}
    return target.casefold() in folded
```

Secure:

```python
REGISTERED_REDIRECTS = {"https://client.example/Callback"}


def is_registered_redirect(target):
    return target in REGISTERED_REDIRECTS
```

## Not a Finding

A redirect is safe when its destination is a constant, selected by an opaque server side key, or
matched by exact equality against a fixed allowlist. A component aware comparison is also safe when
the applicable protocol defines the equivalence and every security relevant component retains its
required case and encoding semantics. A relative path check must reject network path references,
backslashes, encoded separators, and parser ambiguities. Do not report a redirect to attacker
controlled content on the same trusted origin unless the redirect crosses a security boundary or
enables a concrete exploit.
