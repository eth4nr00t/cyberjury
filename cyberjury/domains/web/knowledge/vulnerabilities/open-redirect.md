---
id: open-redirect
title: Open Redirect
impact: MEDIUM
tags: [cwe-601, owasp-a01]
selection_hints: ["redirect(", "redirect_to", "next=", "return_url", "redirect_uri", "continue=", "callback_url", "sendRedirect", "res.redirect", "response.redirect"]
---

# Open Redirect

A redirect target taken from untrusted input without validation lets an attacker send victims to an attacker-controlled site for phishing or OAuth token theft. Validate the target against an allowlist of paths/hosts, or only allow relative paths.

## Python
Vulnerable:
```python
return redirect(request.args["next"])
```
Secure:
```python
target = request.args["next"]
if not target.startswith("/") or target.startswith("//"):
    target = "/"
return redirect(target)
```
