---
id: information-exposure
title: Information Exposure
impact: MEDIUM
tags: [cwe-200, cwe-532, cwe-209, owasp-a02]
selection_hints: ["traceback.format_exc", "stacktrace", "exc_info=True", "logger.exception", "log.info(token", "logger.debug(secret", "print(password", "print(secret", "print(token", "DEBUG = True", "jsonify(error="]
---

# Information Exposure

## Security Condition

Sensitive data such as credentials, tokens, or another person's private information can enable
account compromise or disclose protected records when it is returned to an unauthorized caller or
written to logs or telemetry that a lower trust actor can read. Internal stack traces and query
details can expose exploitable application structure when returned to a remote caller.

## Review Guidance

Report the response construction or log call that crosses the trust boundary, and identify the
sensitive value plus the unauthorized reader. Log only non-secret data and return generic errors.

## Examples

### Sensitive Log Data

Vulnerable:

```python
def record_auth_failure(logger, token):
    logger.info("auth token: %s", token)
```

Secure:

```python
def record_auth_failure(logger, user_id):
    logger.info("auth attempt for user %s", user_id)
```

### Internal Error Responses

Vulnerable:

```python
import traceback


def handle_error(jsonify):
    return jsonify(error=traceback.format_exc()), 500
```

Secure:

```python
def handle_error(jsonify):
    return jsonify(error="internal error"), 500
```

## Not a Finding

This class requires sensitive or internal data and an unauthorized reader. It is not a finding to:

- read or serve a file, make a request, or return ordinary public application data
- log non-sensitive identifiers such as a user id, a request path, or a status
- keep detailed errors in access-controlled server logs that the attacker cannot read

Reaching a file or returning a record is only information exposure when the data returned is
sensitive, for example a secret or another user's PII, or internal, such as a stack trace or a
query. A plain `open(...)` or response is not this weakness. Redaction is safe only when it removes
every sensitive field before the value crosses the final output boundary.
