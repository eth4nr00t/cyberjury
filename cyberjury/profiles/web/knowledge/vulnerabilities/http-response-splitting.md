---
id: http-response-splitting
title: HTTP Response Splitting / Header Injection
impact: MEDIUM
tags: [cwe-113, cwe-93, owasp-a03]
selection_hints: ["set_header", "add_header", "setHeader", "headers.add", "response.headers[\"Location\"", "resp.headers[\"Location\"", "response.headers[\"Set-Cookie\"", "make_response", "set_status", "_set_status", "CRLF", "%0d%0a"]
---

# HTTP Response Splitting / Header Injection

Putting attacker controlled input into a raw response header without rejecting carriage return
and line feed characters lets the attacker inject headers or split the response. The result may
poison a cache, set a cookie, redirect a victim, or create a second response. Report the header or
status-line writer where the untrusted value reaches the wire. A framework header assignment is
reportable only when its effective implementation accepts line breaks.

The HTTP status reason phrase is also part of the wire header block. A response API that accepts a
caller supplied `reason`, stores it, and later writes a status line such as
`HTTP/1.1 400 {reason}` must reject both `\r` and `\n`. Rejecting only `\n` is still vulnerable
because a bare carriage return can terminate or confuse a downstream line parser.

## Python, Raw HTTP Writer

Vulnerable:

```python
def write_echo(stream, value):
    stream.write(f"HTTP/1.1 200 OK\r\nX-Echo: {value}\r\n\r\n".encode())
```

Secure:

```python
def write_echo(stream, value):
    if "\n" in value or "\r" in value:
        raise ValueError("invalid header value")
    stream.write(f"HTTP/1.1 200 OK\r\nX-Echo: {value}\r\n\r\n".encode())
```

Vulnerable:

```python
def write_status(stream, reason):
    if "\n" in reason:
        raise ValueError
    stream.write(f"HTTP/1.1 400 {reason}\r\n\r\n".encode())
```

Secure:

```python
def write_status(stream, reason):
    if "\n" in reason or "\r" in reason:
        raise ValueError
    stream.write(f"HTTP/1.1 400 {reason}\r\n\r\n".encode())
```

## Not a Finding

A header API that rejects both carriage return and line feed before serialization is the expected
control. A constant header value is not attacker controlled. URL encoding or an allowlist is safe
only if its output cannot contain a line break when the final serializer writes it. Do not report
the presence of a response header assignment without tracing an attacker controlled value and
checking the effective serializer.
