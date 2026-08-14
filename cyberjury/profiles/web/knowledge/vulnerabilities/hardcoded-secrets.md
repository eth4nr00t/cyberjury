---
id: hardcoded-secrets
title: Hardcoded Secrets
impact: HIGH
tags: [cwe-798, cwe-259, owasp-a02]
selection_hints: ["api_key =", "password =", "secret =", "token =", "sk_live", "ghp_", "aws_secret", "AKIA", "AIza", "xoxb-", "BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY"]
---

# Hardcoded Secrets

A literal credential, private key, or token in source is exposed to every unauthorized person or
artifact that can read the code. An attacker who obtains a live value can authenticate as the
application, access protected data, or sign trusted content. Report the literal definition when
the value is a real secret that grants current access. Load secrets from an environment variable
or secret manager and rotate a value that has entered source history.

## Python

Vulnerable:

```python
API_KEY = "demo_live_secret_7f43a2b96c18"
```

Secure:

```python
import os


def load_api_key():
    return os.environ["API_KEY"]
```

## Not a Finding

A variable name such as `password` or `token` is not evidence that its value is secret. Do not
report a placeholder, obvious test fixture, public identifier, hash, example credential that no
service accepts, or value loaded from the environment. A live secret in test or example code is
still a finding when it grants access. Reportability depends on the credential's validity and
exposure, not on validation or sanitization of the string.
