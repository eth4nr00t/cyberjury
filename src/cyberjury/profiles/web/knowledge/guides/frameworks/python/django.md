---
id: django
title: Django
kind: framework
language: python
detect:
  files: ["*urls.py", "manage.py", "*settings.py"]
  manifest_hints: ["django"]
  imports: ["from django", "import django"]
entrypoint_globs: ["*urls.py", "*views.py", "*viewsets.py", "*/views/*.py", "*serializers.py", "*api.py", "*consumers.py", "*templates/*.js"]
entrypoint_markers: ["APIView", "ViewSet", "@api_view", "@action", "router.register", "path(", "re_path(", "as_view("]
entrypoint_definition_markers: ["APIView", "ViewSet", "@api_view", "@action", "@extend_schema_view"]
logic_layer_globs: ["*/controllers/*.py", "*controllers.py", "*/models/*.py", "*models.py"]
---

# Django Review Notes

## Attack Surface

### Entrypoints

- Routes live in `urls.py`: `path()` / `re_path()` map a URL to a view.
  `include('app.urls')` mounts a sub-urlconf and the URL prefix accumulates.
  Class-based views are wired as `SomeView.as_view()`.
- Other entrypoints include Django REST Framework viewsets, routers, serializers,
  management commands, signals, and middleware.
- A Django REST Framework `ModelViewSet` exposes inherited list, retrieve, create,
  update, partial update, and destroy actions even when the class does not override those
  methods. Treat every inherited action as part of the entrypoint surface.

## Trust Boundaries

### Authorization and IDOR

- Auth is enforced by decorators such as `@login_required`, DRF permission classes, or
  middleware. Note where it is and where it is missing.
- Compare inherited actions with custom guards on sibling actions. A model permission does
  not enforce a separate business role invariant. Verify inherited actions when create or
  update contains a custom role guard for the same protected object.
- In particular, `ModelViewSet` inherits destroy. A role invariant enforced by create or
  update does not automatically protect deletion. Read the effective destroy path and check
  the same invariant there even when the application class has no `destroy` method.
- Classic IDOR occurs when `Model.objects.get(pk=<user input>)` or `filter(id=...)`
  has no owner or tenant scoping before the object is returned to the caller. Inspect
  every object fetch keyed by a user-supplied id.
- A model level `has_perm("app.view_model")` decision does not owner or tenant scope the
  resulting queryset. In an aggregate search or export, inspect every protected collection
  independently and compare each direct manager query with the application's owner aware
  or object permission filtered query path.

## Review Guidance

### Common Sinks and Gotchas

- SQL: `.raw()`, `.extra()`, `RawSQL`, or string-built SQL via `connection.cursor()`.
- Templates: `mark_safe`, `|safe`, or disabled autoescape on attacker-controlled
  content. `format_html` escapes its interpolated arguments, so its use with a trusted
  format string is a control rather than a sink.
- For caller-authored server templates, a sandbox does not make a live model or ORM object
  a least-privilege context. Trace wrapper functions to `from_string` and `render`, then
  assess whether the context exposes attributes, relationships, or callable behavior beyond
  the endpoint's intended data projection.
- When a rendered path is later used for a filesystem write or move, report the public
  template validation or rendering wrapper as well as the final file operation. The wrapper
  is the reusable source boundary, even when the concrete write is in a signal or consumer.
  Use the enclosing public function or method as the primary symbol, not only an inner
  `render` or string-cleaning helper.
- Settings: `DEBUG=True` is reportable only when an attacker can reach a detailed
  error response that exposes sensitive data. A hardcoded `SECRET_KEY` needs evidence
  that the deployed value is active and enables a concrete forgery or disclosure.
  Untrusted deserialization is a language-level sink, see the Python guide.

## Safe Boundaries

A Django entrypoint is bounded when its active decorator, permission class, or middleware
establishes the caller and each object query scopes to that caller or tenant. Template, query, and
deployment controls must be confirmed at the concrete sink.
