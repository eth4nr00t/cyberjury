---
id: insecure-deserialization
title: Insecure Deserialization
lens: deserialization
impact: CRITICAL
tags: [cwe-502, owasp-a08, rce]
triggers: ["pickle.loads", "pickle.load", "yaml.load", "marshal.loads", "jsonpickle", "ObjectInputStream", "torch.load"]
---

# Insecure Deserialization

Deserializing untrusted bytes with an object-constructing deserializer such as pickle, yaml.load, marshal, or Java ObjectInputStream reconstructs arbitrary objects and can run code. Use a data-only parser such as json.loads or yaml.safe_load for untrusted input.

## Python
Vulnerable:
```python
data = pickle.loads(base64.b64decode(request.data))
config = yaml.load(untrusted)
```
Secure:
```python
data = json.loads(request.data)
config = yaml.safe_load(untrusted)
```
