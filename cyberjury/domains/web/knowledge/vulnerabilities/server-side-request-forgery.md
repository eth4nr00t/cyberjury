---
id: server-side-request-forgery
title: Server-Side Request Forgery
lens: server-side-request-forgery
impact: HIGH
tags: [cwe-918, owasp-a10]
triggers: ["requests.get", "requests.post", "urlopen", "httpx", "fetch(", "url =", "request.args", "webhook", "callback", "http.Get", "http.NewRequest", "http.NewRequestWithContext", "http.Client"]
---

# Server-Side Request Forgery

A server fetches a URL taken from untrusted input without restricting the destination, so an attacker reaches internal targets such as cloud metadata at 169.254.169.254, localhost admin ports, or internal APIs. Validate the host against an allowlist before fetching and reject internal/link-local addresses.

## Python
Vulnerable:
```python
return requests.get(request.args["url"]).text
```
Secure:
```python
if urlparse(url).hostname not in ALLOWED_HOSTS:
    raise ValueError("host not allowed")
return requests.get(url).text
```

Stronger hardening adds defense in depth: enforce `https`, reject credentials in the URL, resolve the host and block private, loopback, and link-local ranges, and re-check after each redirect. Prefer an exact destination allowlist.

## Go
Vulnerable:
```go
resp, err := http.Get(url)
```
A `http.Get`, a `Do` on a `NewRequest`, or any request on a bare `http.Client{}` built from a non-constant URL with no destination check is the sink. The secure form routes the request through a shared client that resolves the host and rejects internal, loopback, and link-local addresses.

## The Call Site Is Enough

Flag the call site, do not wait to read the client. A server-side fetch whose URL argument is not a constant is an SSRF candidate at the line that passes the URL, even when the client that dials lives in a shared helper in another file. The insecure part, a bare client with no allowlist, is usually in that helper, so the absence of a visible destination check at the call site is the signal to report, not a reason to skip. Trace the URL back to its source and report when any attacker-influenced input can steer the destination, whether that input arrives directly in the request or was stored earlier and fetched later. A URL that traces only to a constant or trusted config is not SSRF.

## Not a Finding

A URL fetched only after the parsed hostname is checked against a fixed allowlist by exact equality or membership before the fetch is the expected control and is not reportable without a concrete bypass. Report it only when the check is bypassable, such as a substring, suffix, or `startswith` match, an attacker-controlled allowlist, or a redirect followed with no re-check. Missing internal-IP blocking or redirect re-checks on top of an exact allowlist is hardening advice, not by itself an exploitable finding. A constant or trusted-config URL is not SSRF.
