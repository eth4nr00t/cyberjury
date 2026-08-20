---
id: server-side-request-forgery
title: Server-Side Request Forgery
impact: HIGH
tags: [cwe-918, owasp-a10]
selection_hints: ["requests.get", "requests.post", "httpx.get", "httpx.post", "urlopen", "fetch(", "http.Get", "http.NewRequest", "http.NewRequestWithContext", "http.Client", "request.args.get(\"url\"", "req.query.url", "webhook_url", "callback_url", "169.254.169.254", "metadata.google.internal"]
---

# Server-Side Request Forgery

A server fetches an attacker selected destination using its network position or credentials. The
policy must control the initial destination, every redirect, and the address used for the final
connection. Report the fetch or wrapper where one of those boundaries remains attacker controlled,
and identify the internal service, metadata endpoint, or privileged network action reached.

## Direct Destination Policy

Vulnerable:

```python
import requests


def fetch_preview(url: str) -> str:
    return requests.get(url, timeout=5).text
```

Secure:

```python
from urllib.parse import urlsplit

import requests

ALLOWED_DESTINATIONS = {"https://feeds.example.com"}


def fetch_preview(url: str) -> str:
    parsed = urlsplit(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    if origin not in ALLOWED_DESTINATIONS:
        raise ValueError("destination not allowed")
    return requests.get(url, allow_redirects=False, timeout=5).text
```

The example allowlists an exact trusted origin and disables redirects. If redirects are required,
validate every destination before following it. Do not use a substring, suffix, or string prefix
test as a hostname boundary.

## Redirect Targets

Vulnerable:

```python
from urllib.parse import urljoin


def fetch(client, policy, url):
    policy.require_allowed(url)
    response = client.get(url, allow_redirects=False)
    while response.is_redirect:
        url = urljoin(url, response.headers["Location"])
        response = client.get(url, allow_redirects=False)
    return response
```

Secure:

```python
from urllib.parse import urljoin


def fetch(client, policy, url):
    while True:
        policy.require_allowed(url)
        response = client.get(url, allow_redirects=False)
        if not response.is_redirect:
            return response
        url = urljoin(url, response.headers["Location"])
```

The vulnerable flow checks only the initial URL. A redirect can move the next request to a private
or link local address unless the same policy runs before every hop.

## Resolution and Connection Binding

Vulnerable:

```python
from ipaddress import ip_address
from urllib.parse import urlsplit


def fetch(client, resolver, url):
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname is None:
        raise ValueError("HTTPS destination required")
    address = ip_address(resolver(parsed.hostname))
    if not address.is_global:
        raise ValueError("destination is not public")
    return client.get(url)
```

Secure:

```python
from ipaddress import ip_address
from urllib.parse import urlsplit


def fetch(client, resolver, url):
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname is None:
        raise ValueError("HTTPS destination required")
    address = ip_address(resolver(parsed.hostname))
    if not address.is_global:
        raise ValueError("destination is not public")
    return client.get(url, connect_address=str(address), tls_server_name=parsed.hostname)
```

The vulnerable client resolves the hostname again after validation, which permits a rebinding
answer to select the connection address. The secure boundary pins the validated address while
preserving the hostname for authenticated TLS.

## Trace the Destination Control

A nonconstant URL at a call site is a candidate, not proof of SSRF. Read a reachable shared client
or helper before deciding whether it enforces the destination policy. Do not assume an off-file
control exists, but do not report its absence without reading code that owns the control. Trace the
URL back to its source and report when direct or stored attacker input can steer the destination
and the fetch path lacks an effective policy. The reportable location must be concrete, such as
the fetch call or a wrapper that accepts the unrestricted URL.

## Not a Finding

A constant or trusted config URL is not SSRF. An exact allowlist of trusted destinations is safe
when redirects cannot escape it and DNS resolution is not attacker controlled. A client that
resolves each destination and rejects private, loopback, link local, and reserved addresses before
connecting can safely support broader outbound access when it also prevents DNS rebinding and
rechecks redirects. A shared helper that visibly enforces either policy controls the call sites
that cannot bypass it. Report only a concrete bypass, such as substring matching, user controlled
allowlist entries, unchecked redirects, or a resolution and connection mismatch.
