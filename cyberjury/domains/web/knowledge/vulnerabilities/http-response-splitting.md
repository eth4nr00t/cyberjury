---
id: http-response-splitting
title: HTTP Response Splitting / Header Injection
impact: MEDIUM
tags: [cwe-113, cwe-93, owasp-a03]
selection_hints: ["set_header", "add_header", "setHeader", "headers.add", "response.headers[\"Location\"", "resp.headers[\"Location\"", "response.headers[\"Set-Cookie\"", "make_response", "set_status", "_set_status", "CRLF", "%0d%0a"]
---

# HTTP Response Splitting / Header Injection

Putting untrusted input into a response header such as a redirect Location or Set-Cookie without stripping CR/LF lets an attacker inject headers or split the response. Strip or reject carriage return and line feed characters in any header value built from input. Frameworks often do this, but manual header construction may not.

The HTTP status reason phrase is also part of the wire header block. A response API that accepts a caller supplied `reason`, stores it, and later writes a status line such as `HTTP/1.1 400 {reason}` must reject both `\r` and `\n`. Rejecting only `\n` is still vulnerable because a bare carriage return can terminate or confuse a downstream line parser.

## Python
Vulnerable:
```python
resp.headers["X-Echo"] = request.args["v"]
```
Secure:
```python
v = request.args["v"]
if "\n" in v or "\r" in v:
    abort(400)
resp.headers["X-Echo"] = v
```

Vulnerable:
```python
def set_status(status, reason):
    if "\n" in reason:
        raise ValueError
    self.reason = reason
```
Secure:
```python
def set_status(status, reason):
    if "\n" in reason or "\r" in reason:
        raise ValueError
    self.reason = reason
```
