---
id: jwt-validation
title: JWT Validation Flaw
impact: HIGH
tags: [cwe-347, cwe-345, owasp-a07]
selection_hints: ["jwt.decode", "verify_signature", "verify_signature\": False", "verify_signature=False", "algorithms=None", "algorithms=[]", "alg=none", "alg\":\"none", "\"kid\"", "jwks"]
---

# JWT Validation Flaw

An attacker controls every part of an incoming JWT until its signature and required claims are
verified. Accepting an unsigned token, allowing an attacker chosen algorithm, resolving a key from
an arbitrary location, or using claims before verification lets the attacker forge an identity or
privilege. Report the first use of an unverified claim or the verifier option that accepts the
forged token, and identify the protected operation reached.

Pin the allowed algorithm and trusted issuer. Resolve `kid` only by exact lookup in that issuer's
fixed key set, never as a URL, file path, query fragment, or untrusted key material. Verify the
signature, issuer, audience, expiry, and not-before value before using any claim.

## Python

Vulnerable:

```python
def decode_claims(jwt, token):
    return jwt.decode(token, options={"verify_signature": False})
```

Secure:

```python
def decode_claims(jwt, token, key, audience, issuer):
    return jwt.decode(
        token,
        key,
        algorithms=["RS256"],
        audience=audience,
        issuer=issuer,
        options={"require": ["exp", "iat", "nbf"]},
    )
```

## Not a Finding

A token whose signature and required claims are verified before any security decision is not a
finding. Reading claims from a token already verified earlier in the same reachable flow is safe.
Using the unverified header `kid` only as an exact key in a pinned issuer key set is expected.
Base64 decoding, schema validation, or checking claim types does not substitute for cryptographic
verification.
