---
id: insecure-session-management
title: Insecure Session Management
impact: MEDIUM
tags: [cwe-384, cwe-613, cwe-614, owasp-a07]
selection_hints: ["set_cookie", "httponly", "secure=False", "SESSION_COOKIE_SECURE", "samesite", "SameSite=None", "session_id", "rotate_session", "regenerate_session", "remember_token"]
---

# Insecure Session Management

The session id is not rotated at login, also called fixation, the session cookie lacks HttpOnly/Secure/SameSite, or sessions never expire. Regenerate the session id on authentication, set HttpOnly + Secure + SameSite on the session cookie, and enforce idle and absolute timeouts.

## Python
Vulnerable:
```python
resp.set_cookie("sid", token)
```
Secure:
```python
resp.set_cookie("sid", new_session_id, httponly=True, secure=True, samesite="Lax")
```
