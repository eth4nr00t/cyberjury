---
id: insecure-cryptography
title: Insecure Cryptography
impact: HIGH
tags: [cwe-327, cwe-916, owasp-a02]
selection_hints: ["hashlib.md5", "hashlib.sha1", "crypto.createHash('md5'", "crypto.createHash(\"md5\"", "DES(", "RC4", "ECB", "MODE_ECB", "random.random", "random.randint", "Math.random", "uuid1", "uuid.uuid1", "md5(", "sha1("]
---

# Insecure Cryptography

Weak algorithms such as MD5, SHA-1, DES, or RC4, ECB mode, fast password hashes, nonce reuse,
and non-cryptographic randomness break a security property when used for passwords, signatures,
confidential data, or secret tokens. An attacker may crack credentials, predict tokens, forge
integrity checks, or recover plaintext. Report the security-sensitive hash, encryption, signing,
or token generation operation. State which property fails and how attacker access to its input or
output makes the failure exploitable.

UUIDv1 is not a secret generator. It contains timestamp and host identity structure, so a password
reset token, invite token, API key, session secret, or confirmation token derived from UUIDv1 is
predictable. Encoding or serializing the value does not add entropy. A keyed message
authentication code can provide integrity when its key remains secret, but it does not make an
exposed identifier hide its embedded metadata. Generate secret tokens directly with a CSPRNG.

## Python

Vulnerable:

```python
import hashlib
import random
import uuid


def password_digest(password):
    return hashlib.md5(password.encode()).hexdigest()


def reset_token():
    return f"{random.randint(0, 999999)}-{uuid.uuid1().hex}"
```

Secure:

```python
import hashlib
import secrets


def password_digest(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return salt + digest


def reset_token():
    return secrets.token_urlsafe(32)
```

## JavaScript

Vulnerable:

```javascript
import crypto from "node:crypto"

function passwordDigest(password) {
  return crypto.createHash("md5").update(password).digest("hex")
}

function resetToken() {
  return Math.random().toString(36)
}
```

Secure:

```javascript
import crypto from "node:crypto"

async function passwordDigest(argon2, password) {
  return argon2.hash(password)
}

function resetToken() {
  return crypto.randomBytes(32).toString("base64url")
}
```

## Not a Finding

A weak hash such as MD5 used only for a non-security checksum, cache key, deduplication value, or
ETag is not a finding. A pseudo-random generator used for simulation, sampling, or cosmetic output
is not a finding. The class applies only when the primitive protects passwords, confidentiality,
integrity, token or key secrecy, or nonce uniqueness. Encoding, signing with an attacker known
key, or input validation does not add missing entropy to a predictable secret.
