---
id: flask
title: Flask
kind: framework
language: python
detect:
  manifest_hints: ["flask"]
  imports: ["from flask", "import flask"]
entrypoint_globs: ["*app.py", "*views.py", "*routes.py", "*/views/*.py", "*/blueprints/*.py", "*api.py", "*templates/*.js"]
entrypoint_markers: ["@app.route", ".route(", "Blueprint(", "add_url_rule(", "MethodView", "@app.before_request"]
logic_layer_globs: ["*/models/*.py", "*models.py"]
---

# Flask Review Notes

## Attack Surface

### Entrypoints

- Routes are functions decorated with `@app.route` or `@bp.route`, or registered
  with `add_url_rule`. Blueprints mount a group under a URL prefix. Class views
  subclass `MethodView`.
- Read input from `request.args`, `request.form`, `request.values`,
  `request.json`, `request.files`, `request.headers`, and `request.cookies`, all
  attacker-controlled.

## Trust Boundaries

### Authorization and IDOR

- Auth is enforced by a `@login_required` style decorator, a `before_request`
  hook, or an explicit check in the view. Note where it is and where a route
  lacks it.
- IDOR occurs when a model is fetched by an id from the request with no owner or tenant
  scope, then returned.

## Review Guidance

### Common Sinks and Gotchas

- SSTI: `render_template_string` on input, or `Markup` and `|safe` on unescaped
  input.
- SQL: raw `cursor.execute` or an ORM `text()` built from input.
- Path: `send_file` on a path from input without confinement. `send_from_directory`
  applies a safe join when its directory is trusted, so confirm that boundary before
  reporting `path-traversal`.
- Configuration: a hardcoded `SECRET_KEY` or `debug=True` needs a concrete deployed
  exploit path, such as session forgery or a reachable sensitive debug response. An open
  redirect can occur through `redirect(request.args[...])` when the destination is not
  confined.
- XSS: review a `.js` template under `templates/` as its own unit. Jinja
  `{% autoescape %}` covers only server-side `{{ }}`, not a client-side script that
  builds an HTML string from AJAX data and injects it with `.html(...)` or `innerHTML`.
  A `.html` template that applies `|safe` to stored user input is the same class, trace
  it from the route that renders it.

## Safe Boundaries

A Flask route is bounded when its active decorator or request hook establishes the caller, object
access scopes to that caller or tenant, and escaping, query binding, path confinement, and redirect
validation hold at the concrete sink.
