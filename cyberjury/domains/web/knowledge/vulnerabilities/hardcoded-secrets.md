---
id: hardcoded-secrets
title: Hardcoded Secrets
lens: cryptography
impact: HIGH
tags: [cwe-798, cwe-259, owasp-a02]
triggers: ["api_key =", "API_KEY =", "password =", "secret =", "token =", "sk_live", "ghp_", "aws_secret"]
---

# Hardcoded Secrets

A literal credential, key, or token in source leaks with the code and cannot be rotated easily. Load secrets from environment variables or a secret manager. A variable that reads from the environment or is passed in as a parameter is fine. Only an actual literal value is a finding.

## Python
Vulnerable:
```python
API_KEY = "sk_live_51HxQ...actual-secret"
```
Secure:
```python
api_key = os.environ["API_KEY"]
```
