---
id: jwt-validation
title: JWT Validation Flaw
impact: HIGH
tags: [cwe-347, cwe-345, owasp-a07]
selection_hints: ["jwt.decode", "verify_signature", "verify_signature\": False", "verify_signature=False", "algorithms=None", "algorithms=[]", "alg=none", "alg\":\"none", "\"kid\"", "jwks"]
---

# JWT Validation Flaw

## Security Condition

An attacker controls every JWT header and claim until the application verifies the token against a
trusted policy. Signature and algorithm handling, key selection, claim use ordering, and required
claim validation are separate trust decisions. If a protected action trusts data before all of
them hold, an attacker can forge a principal, choose a verification key or policy, reuse an expired
token, or apply a token issued for another audience or issuer.

## Review Guidance

Report the first protected action reached through a decision that accepts attacker controlled token
data.

## Examples

### Signature and Algorithm Policy

Vulnerable:

```python
def decode_claims(jwt, token, key):
    header = jwt.get_unverified_header(token)
    return jwt.decode(token, key, algorithms=[header["alg"]])
```

Secure:

```python
def decode_claims(jwt, token, key):
    return jwt.decode(
        token,
        key,
        algorithms=["RS256"],
        options={"verify_signature": True},
    )
```

The allowed algorithm comes from trusted verifier configuration, never the unverified header.
Disabling signature verification or permitting an unsigned algorithm has the same missing control.

### Trusted Key Selection

Vulnerable:

```python
def decode_claims(jwt, token, fetch_key):
    header = jwt.get_unverified_header(token)
    key = fetch_key(header["jku"])
    return jwt.decode(token, key, algorithms=["RS256"])
```

Secure:

```python
def decode_claims(jwt, token, issuer_keys):
    header = jwt.get_unverified_header(token)
    key = issuer_keys[header["kid"]]
    return jwt.decode(token, key, algorithms=["RS256"])
```

The secure key set belongs to the expected issuer and is loaded from trusted configuration. The
unverified `kid` is only an exact lookup key. It never becomes a URL, file path, query fragment, or
public key supplied by the token.

### Verification Before Claim Use

Vulnerable:

```python
def authorize(jwt, token, permissions):
    claims = jwt.decode(token, options={"verify_signature": False})
    return permissions.for_subject(claims["sub"])
```

Secure:

```python
def authorize(verify_token, token, permissions):
    claims = verify_token(token)
    return permissions.for_subject(claims["sub"])
```

The `verify_token` boundary must complete signature, issuer, audience, and time validation before it
returns claims. Parsing or type checking a claim is not verification.

### Required Claims

Vulnerable:

```python
def decode_claims(jwt, token, key):
    return jwt.decode(token, key, algorithms=["RS256"])
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

A token whose signature, algorithm, key source, issuer, audience, and required time claims are
verified before any security decision is not a finding. Reading claims from a token verified
earlier in the same reachable flow is safe. Using `kid` only as an exact key in a pinned issuer key
set is expected. Base64 decoding, schema validation, and claim type checks do not substitute for
cryptographic verification.
