---
id: server-side-template-injection
title: Server-Side Template Injection
impact: HIGH
tags: [cwe-1336, owasp-a03, injection, rce]
selection_hints: ["render_template_string", "jinja2.Template", ".from_string", "Jinja2", "Twig", "Velocity", "Handlebars.compile", "template.render", "${{", "<%="]
---

# Server-Side Template Injection

## Security Condition

Building a server side template from untrusted input rather than passing input as template data lets
an attacker inject expressions that the engine evaluates. Depending on the engine and exposed
objects, the attacker can read secrets or execute code.

## Review Guidance

Report the template compilation or dynamic render call where attacker controlled text becomes
template source and an expression can execute. Pass untrusted values as data to a fixed template.

## Examples

### Dynamic Jinja Template Source

Vulnerable:

```python
from jinja2 import Template


def greeting(name: str) -> str:
    return Template("Hello " + name).render()
```

Secure:

```python
from jinja2 import Template


def greeting(name: str) -> str:
    return Template("Hello {{ name }}").render(name=name)
```

## Not a Finding

Rendering attacker controlled values as data in a fixed server selected template is not server
side template injection. Context appropriate output escaping may still be required for cross site
scripting, but escaping output does not make attacker controlled template source safe. A template
chosen from a fixed allowlist is also safe when the attacker cannot modify the selected template.
Do not report client side template rendering under this class.
