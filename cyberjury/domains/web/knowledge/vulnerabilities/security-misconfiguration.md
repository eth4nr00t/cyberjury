---
id: security-misconfiguration
title: Security Misconfiguration
lens: security-misconfiguration
impact: HIGH
tags: [cwe-16, owasp-a05]
triggers: ["debug=True", "debug = True", "app.run(debug", "run(debug=True", "DEBUG = True", "DEBUG=True"]
---

# Security Misconfiguration

A framework or server left in a development or permissive mode in production turns a setting
into an exploit. Flask `debug=True` serves the Werkzeug interactive debugger, whose console
runs arbitrary Python on any unhandled exception, a remote code execution. Django
`DEBUG = True` returns full tracebacks that leak `SECRET_KEY`, settings, and environment, which
an attacker uses to forge sessions or signed tokens. Report a setting only when its value in
the code shown is itself the exploit, not a missing best-practice header.

## Vulnerable
```python
app = Flask(__name__)
app.run(host="0.0.0.0", debug=True)  # Werkzeug console runs arbitrary code on any error
```

## Secure
```python
app = Flask(__name__)
app.run(host="0.0.0.0", debug=os.environ.get("FLASK_DEBUG") == "1")  # off in production
```

## Vulnerable
```python
DEBUG = True  # production tracebacks expose SECRET_KEY, settings, and env
ALLOWED_HOSTS = ["*"]
```

## Secure
```python
DEBUG = os.environ.get("DJANGO_DEBUG") == "1"
ALLOWED_HOSTS = ["app.example.com"]
```

## Not a Finding

A missing security header such as CSP, HSTS, or X-Frame-Options on its own, a verbose error
message that carries no secret, or any setting that only matters if a production config is
leaked, is not a finding. Report only a setting whose value in the code shown is itself the
exploit, such as the debugger console enabled or production tracebacks turned on.
