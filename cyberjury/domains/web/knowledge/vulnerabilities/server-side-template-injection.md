---
id: server-side-template-injection
title: Server-Side Template Injection
lens: server-side-template-injection
impact: HIGH
tags: [cwe-1336, owasp-a03, injection, rce]
triggers: ["render_template_string", "Template(", "from_string", "Jinja2", "{{", "Twig", "Velocity", "Handlebars.compile"]
---

# Server-Side Template Injection

Building a template from untrusted input rather than passing input as template data lets an attacker inject template syntax that the engine evaluates, often reaching RCE. Pass untrusted values as data to a fixed template. Never compile a template from user input.

## Python, Jinja2
Vulnerable:
```python
render_template_string("Hello " + request.args["name"])  # name becomes template
```
Secure:
```python
render_template_string("Hello {{ name }}", name=request.args["name"])
```
