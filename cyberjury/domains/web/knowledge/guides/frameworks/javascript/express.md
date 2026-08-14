---
id: express
title: Express
kind: framework
language: javascript
detect:
  manifest_hints: ["express"]
  imports: ["require('express')", "require(\"express\")", "from 'express'"]
entrypoint_files: ["*/controllers/*.js", "*router*.js", "*/routes/*.ts", "*/controllers/*.ts", "*router*.ts"]
entrypoint_markers: ["express()", "app.get(", "app.post(", "app.use(", "router.get(", "router.post("]
logic_layer_files: ["*/services/*.ts", "*/repositories/*.ts", "*/dao/*.ts", "*/models/*.ts"]
public_api_patterns: []
---
# Express Review Notes

Works the same in JavaScript and TypeScript. See the JavaScript guide for the
runtime sinks.

## Entrypoints

- Routes are `app.get` / `app.post` / `router.*`, and a `Router` mounted with
  `app.use("/prefix", router)`. The handler is `(req, res, next)`. Input is
  `req.params`, `req.query`, `req.body`, `req.headers`, and `req.cookies`.

## Authorization and IDOR

- Auth is middleware, passed to `app.use` or per route. The flaw to hunt is a
  route mounted before the auth middleware, or one that omits the middleware its
  siblings have, so order and placement matter.
- IDOR occurs when a record is loaded by `req.params.id` with no owner or tenant scope.

## Common Sinks and Gotchas

- SQL and NoSQL: a query built by string concatenation, or a Mongo filter built
  straight from `req.body`, the operator-injection sink.
- Command: `child_process.exec` from input. Code: `eval` from input.
- Path: `res.sendFile` or `path.join` on a path from input, the traversal sink.
- Open redirects and prototype pollution: `res.redirect(req.query...)` can redirect to
  attacker input, and a body merge can reach prototype keys.
- Mass assignment: a body spread whole into a model or an ORM create.
