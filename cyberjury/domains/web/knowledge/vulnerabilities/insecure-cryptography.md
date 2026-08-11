---
id: insecure-cryptography
title: Insecure Cryptography
impact: HIGH
tags: [cwe-327, cwe-916, owasp-a02]
selection_hints: ["hashlib.md5", "hashlib.sha1", "crypto.createHash('md5'", "crypto.createHash(\"md5\"", "DES(", "RC4", "ECB", "MODE_ECB", "random.random", "random.randint", "Math.random", "uuid1", "uuid.uuid1", "md5(", "sha1("]
---

# Insecure Cryptography

Weak algorithms such as MD5, SHA-1, DES, or RC4, ECB mode, fast hashes for passwords, static or reused IVs, and non-cryptographic randomness for security values are exploitable. Use AES-GCM or ChaCha20-Poly1305, bcrypt/scrypt/argon2 for passwords, a fresh random nonce per message, and a CSPRNG such as secrets or os.urandom.

UUIDv1 is not a secret generator. It contains timestamp and host identity structure, so a password reset token, invite token, API key, sharing token, session secret, or confirmation token derived from `uuid.uuid1`, `uuid1`, or a helper that wraps them is predictable. Signing or serializing that value does not add entropy when the signing key or salt is tenant controlled, public, weak, or reused as the token namespace. Generate security tokens directly with a CSPRNG such as `secrets.token_urlsafe`.

## Python
Vulnerable:
```python
hashlib.md5(password.encode()).hexdigest()
token = str(random.randint(0, 999999))
token = uuid.uuid1().hex
```
Secure:
```python
bcrypt.hashpw(password.encode(), bcrypt.gensalt())
token = secrets.token_urlsafe(32)
```

## Not a Finding

A weak hash such as MD5 used only for a non-security checksum, a cache key, deduplication, or an ETag is not a finding. The class applies to security-sensitive use, password hashing, signatures, token or key generation, IV or nonce reuse, and randomness for secrets.
