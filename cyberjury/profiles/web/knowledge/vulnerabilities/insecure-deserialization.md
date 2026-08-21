---
id: insecure-deserialization
title: Insecure Deserialization
impact: CRITICAL
tags: [cwe-502, owasp-a08, rce]
selection_hints: ["pickle.loads", "pickle.load", "yaml.load", "yaml.Loader", "FullLoader", "marshal.loads", "jsonpickle", "ObjectInputStream", "readObject", "BinaryFormatter", "torch.load", "joblib.load", "sys.modules[", "importlib.import_module("]
---

# Insecure Deserialization

## Security Condition

Deserialization is unsafe when untrusted data selects the runtime type or callable that an
application reconstructs. This includes object-building formats such as pickle and
`ObjectInputStream`. It also includes data-only formats whose module name, class name, or type name
is resolved and invoked without a closed allowlist. Parsing the envelope as JSON does not make the
later object reconstruction safe. The selected constructor or callback can then execute code, read
a file, make a network request, or perform an unauthorized state change with application authority.

## Review Guidance

Use a data-only parser for untrusted bytes. When reconstruction is required, map a closed set of
wire type identifiers to explicitly approved classes before constructing them.

Report the deserialization or dynamic construction call where an attacker controlled payload can
select the runtime type or callable. Show that construction invokes behavior with a concrete
impact such as code execution, file access, a network request, or an unauthorized state change.
Do not stop at the fact that an object is reconstructed.

## Examples

### Unsafe Object Deserialization

Vulnerable:

```python
import base64
import pickle


def restore(encoded):
    return pickle.loads(base64.b64decode(encoded))
```

Secure:

```python
import base64
import json


def restore(encoded):
    return json.loads(base64.b64decode(encoded))
```

### Dynamic Type Resolution

Vulnerable:

```python
import importlib
import json


def construct(encoded):
    record = json.loads(encoded)
    module = importlib.import_module(record["module"])
    return getattr(module, record["type"])(*record["args"])
```

Secure:

```python
import json


def created_event(value):
    return {"type": "created", "value": value}


def deleted_event(value):
    return {"type": "deleted", "value": value}


def construct(encoded):
    types = {"created": created_event, "deleted": deleted_event}
    record = json.loads(encoded)
    return types[record["type"]](record["value"])
```

## Not a Finding

Dynamic loading alone is not insecure deserialization. Do not report a constant module or class,
a type selected only by trusted configuration, or a type selected from a closed allowlist of
approved classes. The attacker must control the serialized type or callable identity and reach its
construction or invocation.
