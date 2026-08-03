---
id: cors-misconfiguration
title: CORS Misconfiguration
lens: cross-origin
impact: MEDIUM
tags: [cwe-942, owasp-a05]
triggers: ["Access-Control-Allow-Origin", "Access-Control-Allow-Credentials", "cors(", "origin", "req.headers.origin", "ACAO"]
---

# CORS Misconfiguration

A server that reflects the request `Origin` back into `Access-Control-Allow-Origin` while
also sending `Access-Control-Allow-Credentials: true` lets any website read the
authenticated responses of a logged-in victim, so a malicious page steals the victim's
data or tokens cross-origin. Reflecting the origin, or trusting it by a substring or
suffix match, is the exploitable form. Validate the origin against an exact allowlist and
send credentials only to those origins.

## Vulnerable
```javascript
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", req.headers.origin)   // reflects any origin
  res.setHeader("Access-Control-Allow-Credentials", "true")
  next()
})
```

## Secure
```javascript
const ALLOWED = new Set(["https://app.example.com"])
app.use((req, res, next) => {
  if (ALLOWED.has(req.headers.origin)) {
    res.setHeader("Access-Control-Allow-Origin", req.headers.origin)
    res.setHeader("Access-Control-Allow-Credentials", "true")
  }
  next()
})
```

## Not a Finding

A wildcard `Access-Control-Allow-Origin: *` without `Allow-Credentials` on data that is
already public is not a finding, the browser blocks the credentialed case. An exact-match
allowlist is the expected control. Report it only when the origin is reflected, matched by
substring, suffix, or `startsWith`, or read from attacker-controlled config, together with
credentials or access to non-public data.
