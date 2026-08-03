---
id: open-redirect
title: Open Redirect
lens: open-redirect
impact: MEDIUM
tags: [cwe-601, owasp-a01]
triggers: ["redirect(", "Location", "next=", "return_url", "redirect_uri", "sendRedirect", "res.redirect"]
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
