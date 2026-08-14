---
id: insecure-transport
title: Insecure Transport
impact: HIGH
tags: [cwe-319, cwe-295, owasp-a02]
selection_hints: ["http://", "verify=False", "CERT_NONE", "check_hostname=False", "_create_unverified_context", "rejectUnauthorized: false", "InsecureSkipVerify", "tls.Config{InsecureSkipVerify"]
---

# Insecure Transport

Sending credentials or other sensitive data over cleartext HTTP lets an on-path attacker read or
alter it. Disabling certificate or hostname verification lets the attacker impersonate the remote
service even when TLS is used. Report the reachable client call or effective transport
configuration where sensitive data crosses a real network boundary without authenticated TLS.
State the sensitive asset and the attacker position. Use HTTPS and retain certificate and
hostname verification.

## Python

Vulnerable:

```python
def send_credentials(client, credentials):
    return client.post("http://api.example.com/login", data=credentials)


def fetch_data(client):
    return client.get("https://api.example.com/data", verify=False)
```

Secure:

```python
def send_credentials(client, credentials):
    return client.post("https://api.example.com/login", data=credentials)


def fetch_data(client):
    return client.get("https://api.example.com/data")
```

## Not a Finding

`http://localhost`, `http://127.0.0.1`, a test fixture, or a non-sensitive documentation link is
not insecure transport. An internal connection is not automatically safe, but it is reportable
only with sensitive data and a plausible untrusted network path. A custom certificate authority
with hostname verification intact is not disabled verification. Input validation or URL encoding
does not authenticate the peer or protect cleartext data.
