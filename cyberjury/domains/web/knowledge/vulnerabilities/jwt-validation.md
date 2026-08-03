---
id: jwt-validation
title: JWT Validation Flaw
lens: authentication
impact: HIGH
tags: [cwe-347, cwe-345, owasp-a07]
triggers: ["jwt.decode", "verify=False", "verify_signature", "algorithms"]
---

# JWT Validation Flaw

Accepting a JWT without verifying its signature, allowing the "none" algorithm, or reading claims before verification lets an attacker forge identity. Verify the signature with a fixed allowed algorithm, choose the key from trusted issuer metadata by a trusted `kid`, and validate iss, aud, exp, and nbf before using any claim.

## Python
Vulnerable:
```python
claims = jwt.decode(token, options={"verify_signature": False})
jwt.decode(token, key, algorithms=["none"])
```
Secure:
```python
claims = jwt.decode(
    token,
    key,
    algorithms=["RS256"],
    audience=AUD,
    issuer=ISS,
    options={"require": ["exp", "iat", "nbf"]},
)
```

## Not a Finding

A token whose signature is verified with a fixed algorithm before any claim is read is not a finding. Reading claims from a token already verified earlier in the same flow is not a finding.
