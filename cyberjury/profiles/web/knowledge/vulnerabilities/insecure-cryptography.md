---
id: insecure-cryptography
title: Insecure Cryptography
impact: HIGH
tags: [cwe-327, cwe-916, owasp-a02]
selection_hints: ["hashlib.md5", "hashlib.sha1", "crypto.createHash('md5'", "crypto.createHash(\"md5\"", "DES(", "RC4", "ECB", "MODE_ECB", "random.random", "random.randint", "Math.random", "uuid1", "uuid.uuid1", "md5(", "sha1("]
---

# Insecure Cryptography

## Security Condition

Cryptography is insecure when the chosen primitive or its use fails the property an application
depends on. Password storage needs a slow password hash. Confidential data needs authenticated
encryption. Secret tokens need unpredictable entropy. Nonce based encryption needs a unique nonce
for each key. An attacker with the corresponding stored digest, ciphertext, token opportunity, or
chosen encryption input can otherwise recover credentials, read or forge protected data, predict a
secret, or break confidentiality across repeated messages.

## Review Guidance

Report the security operation, the required property, and the attacker access that makes the failure
exploitable.

## Examples

### Password Storage

Vulnerable:

```python
import hashlib


def password_digest(password):
    return hashlib.md5(password.encode()).hexdigest()
```

Secure:

```python
import hashlib
import secrets


def password_digest(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return salt + digest
```

General purpose fast hashes such as MD5 and SHA-1 do not provide a password work factor. Use a
password hashing construction with a unique salt and an application calibrated cost.

### Authenticated Encryption

Vulnerable:

```javascript
import crypto from "node:crypto"

function encrypt(key, plaintext) {
  const cipher = crypto.createCipheriv("aes-256-ecb", key, null)
  return Buffer.concat([cipher.update(plaintext), cipher.final()])
}
```

Secure:

```javascript
import crypto from "node:crypto"

function encrypt(key, plaintext) {
  const nonce = crypto.randomBytes(12)
  const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce)
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()])
  return { nonce, ciphertext, tag: cipher.getAuthTag() }
}
```

The receiver must verify the authentication tag before releasing plaintext. Encryption without
integrity does not control attacker modification.

### Secret Generation

Vulnerable:

```python
import random
import uuid


def reset_token():
    return f"{random.randint(0, 999999)}-{uuid.uuid1().hex}"
```

Secure:

```python
import secrets


def reset_token():
    return secrets.token_urlsafe(32)
```

UUIDv1 is not a secret generator. It exposes timestamp and host structure. Encoding, serializing,
or signing a predictable value does not add secrecy unless the construction already includes
unpredictable secret material.

### Nonce Uniqueness

Vulnerable:

```python
def encrypt(aead, key, plaintext):
    nonce = b"\x00" * 12
    return nonce, aead.encrypt(key, nonce, plaintext)
```

Secure:

```python
import secrets


def encrypt(aead, key, plaintext):
    nonce = secrets.token_bytes(12)
    return nonce, aead.encrypt(key, nonce, plaintext)
```

The required nonce size and uniqueness rule come from the selected algorithm. Random generation is
safe only when its collision risk is acceptable for the number of encryptions under one key.

## Not a Finding

A weak hash such as MD5 used only for a non-security checksum, cache key, deduplication value, or
ETag is not a finding. A pseudorandom generator used for simulation, sampling, or cosmetic output
does not protect a secret and is not a finding. Report only when the primitive protects passwords,
confidentiality, integrity, token or key secrecy, or nonce uniqueness. A standard authenticated
primitive is safe when keys, nonce rules, parameters, and tag verification follow its contract.
