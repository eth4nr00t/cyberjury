---
id: information-exposure
title: Information Exposure
lens: information-exposure
impact: MEDIUM
tags: [cwe-200, cwe-532, cwe-209, owasp-a02]
triggers: ["traceback.format_exc", "str(e)", "log.info(token", "logger.debug(secret", "print(password", "DEBUG = True", "jsonify(error="]
---

# Information Exposure

Sensitive data such as secrets, tokens, or PII written to logs, or internal detail such as stack traces, exception messages, or debug output returned to the client, helps an attacker and widens breach impact. Log only non-secret data, return a generic error to the caller, and keep detail server-side.

## Python
Vulnerable:
```python
logger.info("auth token: %s", token)
return jsonify(error=traceback.format_exc()), 500
```
Secure:
```python
logger.info("auth attempt for user %s", user_id)
app.logger.exception("auth failed")
return jsonify(error="internal error"), 500
```

## Not a Finding

This is about leaking secrets/PII or internal detail. It is not a finding to:
- read or serve a file, make a request, or return ordinary application data,
- log non-sensitive identifiers such as a user id, a request path, or a status.

Reaching a file or returning a record is only information exposure when the data
returned is itself sensitive, for example a secret or another user's PII, or internal such as a stack
trace or a query. A plain `open(...)` or response is not this weakness.
