---
id: cross-site-request-forgery
title: Cross-Site Request Forgery
lens: cross-origin
impact: HIGH
tags: [cwe-352, owasp-a01]
triggers: ["@app.route", "methods=[\"POST\"", "csrf", "SameSite", "csrf_exempt", "@csrf", "form"]
---

# Cross-Site Request Forgery

A state-changing request is accepted using only ambient credentials such as a session cookie with no anti-CSRF token or SameSite protection, so a malicious site can make the victim's browser perform the action. Require a CSRF token, or SameSite=Strict or Lax cookies plus an origin check, on every state-changing endpoint.

## Python
Vulnerable:
```python
@app.route("/account/email", methods=["POST"])
@csrf.exempt  # disables CSRF protection on a state-changing route
def change_email():
    current_user.email = request.form["email"]
    db.commit()
```
Secure: keep CSRF protection on. Validate the token, or set the session cookie `SameSite="Lax"` and check the Origin header.

## OAuth Login CSRF

An OAuth callback that redeems the `code` and starts a session is a state-changing request. When it does not check a `state` value bound to the user's session, an attacker can hand the victim a code from the attacker's account and log the victim into it, login CSRF.

Vulnerable:
```python
@app.route("/oauth/callback")
def callback():
    token = exchange_code(request.args["code"])  # no state check, any code is accepted
    login(token)
    return redirect("/")
```
Secure: issue a random `state` at authorize time, keep it in the session, and reject the callback unless the returned `state` matches.

## Not a Finding

An endpoint authenticated by a bearer token read from JavaScript and sent in the `Authorization` header, not by an ambient cookie, is not CSRF. CSRF needs a credential the browser attaches automatically.
