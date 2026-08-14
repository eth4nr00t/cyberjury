---
id: security-misconfiguration
title: Security Misconfiguration
impact: HIGH
tags: [cwe-16, owasp-a05]
selection_hints: ["debug=True", "DEBUG = True", "FLASK_DEBUG", "app.run(debug", "run(debug=True", "ALLOWED_HOSTS = [\"*\"]", "CORS_ALLOW_ALL_ORIGINS"]
---

# Security Misconfiguration

A framework or server left in a development or permissive mode in production can turn a setting
into an exploit. For example, an externally reachable Werkzeug debugger can expose an interactive
console that executes Python when its access control is absent or can be bypassed. Report the
production configuration line that enables the dangerous feature only when repository evidence
also establishes attacker reachability and the concrete exploit condition. A setting that merely
weakens hardening or might be overridden at deployment is not enough.

## Vulnerable

```python
from flask import Flask

app = Flask(__name__)
app.run(host="0.0.0.0", debug=True)
```

## Secure

```python
from flask import Flask

app = Flask(__name__)
app.run(host="127.0.0.1", debug=False)
```

## Not a Finding

A missing security header such as CSP, HSTS, or X-Frame-Options on its own, a wildcard host list,
a verbose error message that carries no secret, or a development default with no evidence that it
is used in production is not a finding. Environment driven debug configuration is not inherently
safe or vulnerable. Trace the deployed value. Report only when the dangerous feature is enabled,
attacker reachable, and has a concrete exploit such as an exposed debugger console.
