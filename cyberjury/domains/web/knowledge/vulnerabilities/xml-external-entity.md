---
id: xml-external-entity
title: XML External Entity
lens: xml-external-entity
impact: HIGH
tags: [cwe-611, owasp-a03, injection]
triggers: ["etree", "lxml", "xml.dom", "minidom", "sax", "resolve_entities", "DocumentBuilderFactory", "XMLReader"]
---

# XML External Entity

An XML parser that resolves external entities on untrusted input lets an attacker read local files, perform SSRF, or cause DoS via entity expansion. Disable external entity and DTD processing, or use a parser that does so by default such as defusedxml.

## Python
Vulnerable:
```python
from lxml import etree

parser = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=False)
doc = etree.fromstring(untrusted_xml, parser)  # external entities resolved
```
Secure:
```python
import defusedxml.ElementTree as ET

doc = ET.fromstring(untrusted_xml)
```

## Not a Finding

An XML parser configured to disable DTD processing and external entity resolution is not
vulnerable, in any language or library: for example Python `defusedxml` or
`etree.XMLParser(resolve_entities=False, no_network=True)`, a Java factory with
`disallow-doctype-decl` set, or a parser whose defaults already disable both. Report plain
parsing only when external entity or DTD resolution is actually enabled on untrusted input.
