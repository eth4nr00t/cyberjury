---
id: django
title: Django
kind: framework
language: python
detect:
  files: ["*urls.py", "manage.py", "*settings.py"]
  manifest_hints: ["django"]
  imports: ["from django", "import django"]
entrypoint_files: ["*urls.py", "*views.py", "*viewsets.py", "*/views/*.py", "*serializers.py", "*api.py", "*consumers.py", "*templates/*.js"]
entrypoint_markers: ["APIView", "ViewSet", "@api_view", "@action", "router.register", "path(", "re_path(", "as_view("]
logic_layer_files: ["*/controllers/*.py", "*controllers.py", "*/models/*.py", "*models.py"]
public_api_patterns: []
---

# Django Review Notes

## Attack Surface

### Entrypoints

- Routes live in `urls.py`: `path()` / `re_path()` map a URL to a view.
  `include('app.urls')` mounts a sub-urlconf and the URL prefix accumulates.
  Class-based views are wired as `SomeView.as_view()`.
- Other entrypoints include Django REST Framework viewsets, routers, serializers,
  management commands, signals, and middleware.

## Trust Boundaries

### Authorization and IDOR

- Auth is enforced by decorators such as `@login_required`, DRF permission classes, or
  middleware. Note where it is and where it is missing.
- Classic IDOR occurs when `Model.objects.get(pk=<user input>)` or `filter(id=...)`
  has no owner or tenant scoping before the object is returned to the caller. Inspect
  every object fetch keyed by a user-supplied id.

## Review Guidance

### Common Sinks and Gotchas

- SQL: `.raw()`, `.extra()`, `RawSQL`, or string-built SQL via `connection.cursor()`.
- Templates: `mark_safe`, `|safe`, or disabled autoescape on attacker-controlled
  content. `format_html` escapes its interpolated arguments, so its use with a trusted
  format string is a control rather than a sink.
- Settings: `DEBUG=True` is reportable only when an attacker can reach a detailed
  error response that exposes sensitive data. A hardcoded `SECRET_KEY` needs evidence
  that the deployed value is active and enables a concrete forgery or disclosure.
  Untrusted deserialization is a language-level sink, see the Python guide.

## Safe Boundaries

A Django entrypoint is bounded when its active decorator, permission class, or middleware
establishes the caller and each object query scopes to that caller or tenant. Template, query, and
deployment controls must be confirmed at the concrete sink.
