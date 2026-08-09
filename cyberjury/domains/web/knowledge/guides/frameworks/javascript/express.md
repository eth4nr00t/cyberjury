---
id: express
title: Express
kind: framework
language: javascript
detect:
  manifest_hints: ["express"]
  imports: ["require('express')", "require(\"express\")", "from 'express'"]
entrypoint_files: ["*app.ts", "*server.ts", "*/routes/*.ts", "*/controllers/*.js", "*/controllers/*.ts", "*router*.js", "*router*.ts"]
entrypoint_markers: ["express()", "app.get(", "app.post(", "app.use(", "router.get(", "router.post(", ".get(", ".post(", "req.params", "req.query", "req.body"]
logic_layer_files: ["*/services/*.ts", "*/models/*.ts", "*/repositories/*.ts", "*/dao/*.ts"]
public_api_patterns: []
---
# Express Review Notes

Works the same in JavaScript and TypeScript. See the JavaScript guide for the
runtime sinks.

## Entrypoints
- Routes are `app.get` / `app.post` / `router.*`, and a `Router` mounted with
  `app.use("/prefix", router)`. The handler is `(req, res, next)`. Input is
  `req.params`, `req.query`, `req.body`, `req.headers`, and `req.cookies`.

## Authorization / IDOR
- Auth is middleware, passed to `app.use` or per route. The flaw to hunt is a
  route mounted before the auth middleware, or one that omits the middleware its
  siblings have, so order and placement matter.
- IDOR: a record loaded by `req.params.id` with no owner or tenant scope.

## Common Sinks / Gotchas
- SQL and NoSQL: a query built by string concatenation, or a Mongo filter built
  straight from `req.body`, the operator-injection sink.
- Command: `child_process.exec` from input. Code: `eval` from input.
- Path: `res.sendFile` or `path.join` on a path from input, the traversal sink.
- Open redirect via `res.redirect(req.query...)`, and prototype pollution from a
  body merge.
- A body spread whole into a model or an ORM create is mass assignment.
