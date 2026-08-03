---
id: http-response-splitting
title: HTTP Response Splitting / Header Injection
lens: http-response-splitting
impact: MEDIUM
tags: [cwe-113, cwe-93, owasp-a03]
triggers: ["set_header", "add_header", "Location", "Set-Cookie", "response.headers", "resp.headers", "make_response", "setHeader"]
---

# HTTP Response Splitting / Header Injection

Putting untrusted input into a response header such as a redirect Location or Set-Cookie without stripping CR/LF lets an attacker inject headers or split the response. Strip or reject newline characters in any header value built from input. Frameworks often do this, but manual header construction may not.

## Python
Vulnerable:
```python
resp.headers["X-Echo"] = request.args["v"]  # v may contain \r\n
```
Secure:
```python
v = request.args["v"]
if "\n" in v or "\r" in v:
    abort(400)
resp.headers["X-Echo"] = v
```
