---
id: xml-external-entity
title: XML External Entity
impact: HIGH
tags: [cwe-611, owasp-a03, injection]
selection_hints: ["etree", "lxml", "xml.dom", "minidom", "sax", "resolve_entities", "no_network=False", "load_dtd=True", "DocumentBuilderFactory", "XMLReader", "setFeature"]
---

# XML External Entity

## Security Condition

An XML parser that resolves external entities on untrusted input lets an attacker read local files,
make requests from the server, or exhaust resources through entity expansion.

## Review Guidance

Report the parser construction or parse call where attacker controlled XML reaches enabled DTD or
external entity processing. Disable both features or use a parser that disables them by contract.

## Examples

### External Entity Resolution

Vulnerable:

```python
from lxml import etree


def parse_document(xml: bytes):
    parser = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=False)
    return etree.fromstring(xml, parser)
```

Secure:

```python
import defusedxml.ElementTree as ET


def parse_document(xml: bytes):
    return ET.fromstring(xml)
```

## Not a Finding

An XML parser configured to disable DTD processing and external entity resolution is not
vulnerable. Examples include Python `defusedxml`,
`etree.XMLParser(resolve_entities=False, load_dtd=False, no_network=True)`, and parsers whose
documented defaults disable both features. Do not infer vulnerability from a parser name alone.
Report only when external entity or DTD processing is enabled on attacker controlled XML. Entity
substitution from a fixed server supplied map is safe when the attacker cannot declare or alter
the mapped entities.
