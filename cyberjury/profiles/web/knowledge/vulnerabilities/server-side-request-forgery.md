---
id: server-side-request-forgery
title: Server-Side Request Forgery
impact: HIGH
tags: [cwe-918, owasp-a10]
selection_hints: ["requests.get", "requests.post", "httpx.get", "httpx.post", "urlopen", "fetch(", "http.Get", "http.NewRequest", "http.NewRequestWithContext", "http.Client", "request.args.get(\"url\"", "req.query.url", "webhook_url", "callback_url", "169.254.169.254", "metadata.google.internal"]
---

# Server-Side Request Forgery

A server fetches a URL taken from untrusted input without restricting the destination. An attacker
can reach cloud metadata, localhost admin ports, or internal APIs using the server's network
position and credentials. Trace the URL through wrappers and report the call that performs the
fetch, or the boundary that accepts an attacker selected destination without an effective policy.
Prefer an exact destination allowlist. When arbitrary external hosts are required, resolve and pin
the destination, reject private, loopback, link local, and reserved addresses, and apply the same
policy after every redirect.

## Python

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

## Go

Vulnerable:

```go
package preview

import "net/http"

func Fetch(url string) (*http.Response, error) {
	return http.Get(url)
}
```

Secure:

```go
package preview

import (
	"errors"
	"net/http"
	"net/url"
)

func Fetch(rawURL string) (*http.Response, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host != "feeds.example.com" {
		return nil, errors.New("destination not allowed")
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	return client.Get(parsed.String())
}
```

An `http.Get`, a `Do` on a `NewRequest`, or another client call is the sink when attacker input can
steer its destination and no effective destination policy exists.

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
