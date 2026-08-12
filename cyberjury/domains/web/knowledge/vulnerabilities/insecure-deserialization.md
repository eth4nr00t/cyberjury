---
id: insecure-deserialization
title: Insecure Deserialization
impact: CRITICAL
tags: [cwe-502, owasp-a08, rce]
selection_hints: ["pickle.loads", "pickle.load", "yaml.load", "yaml.Loader", "FullLoader", "marshal.loads", "jsonpickle", "ObjectInputStream", "readObject", "BinaryFormatter", "torch.load", "joblib.load", "sys.modules[", "importlib.import_module("]
---

# Insecure Deserialization

Deserialization is unsafe when untrusted data selects the runtime type or callable that an
application reconstructs. This includes object-building formats such as pickle and
`ObjectInputStream`. It also includes data-only formats whose module name, class name, or type
name is resolved and invoked without a closed allowlist. Parsing the envelope as JSON does not
make the later object reconstruction safe.

Use a data-only parser for untrusted bytes. When reconstruction is required, map a closed set of
wire type identifiers to explicitly approved classes before constructing them.

## Python
Vulnerable:
```python
data = pickle.loads(base64.b64decode(request.data))
config = yaml.load(untrusted)

record = json.loads(request.data)
module = importlib.import_module(record["module"])
value = getattr(module, record["type"])(*record["args"])
```
Secure:
```python
data = json.loads(request.data)
config = yaml.safe_load(untrusted)

types = {"created": CreatedEvent, "deleted": DeletedEvent}
record = json.loads(request.data)
value = types[record["type"]](*record["args"])
```

## Not a Finding

Dynamic loading alone is not insecure deserialization. Do not report a constant module or class,
a type selected only by trusted configuration, or a type selected from a closed allowlist of
approved classes. The attacker must control the serialized type or callable identity and reach its
construction or invocation.
