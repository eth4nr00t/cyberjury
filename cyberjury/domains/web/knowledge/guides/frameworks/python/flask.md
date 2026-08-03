---
id: flask
title: Flask
kind: framework
language: python
detect:
  manifest: ["flask"]
  imports: ["from flask", "import flask"]
entrypoint_files: ["*app.py", "*views.py", "*routes.py", "*/views/*.py", "*/blueprints/*.py", "*api.py", "*templates/*.js"]
entrypoint_markers: ["@app.route", ".route(", "Blueprint(", "add_url_rule(", "MethodView", "@app.before_request"]
logic_layers: ["*/services/*.py", "*services.py", "*/models/*.py", "*models.py", "*/repositories/*.py", "*/dao/*.py"]
---
# Flask Review Notes

## Entrypoints
- Routes are functions decorated with `@app.route` or `@bp.route`, or registered
  with `add_url_rule`. Blueprints mount a group under a URL prefix. Class views
  subclass `MethodView`.
- Read input from `request.args`, `request.form`, `request.values`,
  `request.json`, `request.files`, `request.headers`, and `request.cookies`, all
  attacker-controlled.

## Authorization / IDOR
- Auth is enforced by a `@login_required` style decorator, a `before_request`
  hook, or an explicit check in the view. Note where it is and where a route
  lacks it.
- IDOR: a model fetched by an id from the request with no owner or tenant scope,
  then returned.

## Common Sinks / Gotchas
- SSTI: `render_template_string` on input, or `Markup` and `|safe` on unescaped
  input.
- SQL: raw `cursor.execute` or an ORM `text()` built from input.
- Path: `send_file` or `send_from_directory` with a path from input, the traversal
  sink.
- A hardcoded `SECRET_KEY`, `debug=True` in production, and an open redirect via
  `redirect(request.args[...])`.
- XSS in a `.js` template under `templates/`, reviewed as its own unit. Jinja
  `{% autoescape %}` covers only server-side `{{ }}`, not a client-side script that
  builds an HTML string from AJAX data and injects it with `.html(...)` or `innerHTML`.
  A `.html` template that applies `|safe` to stored user input is the same class, trace
  it from the route that renders it.
