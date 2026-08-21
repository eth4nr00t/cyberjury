---
id: javascript
title: JavaScript
kind: language
detect:
  files: ["*.js", "*.mjs", "*.cjs", "*.jsx"]
entrypoint_globs: ["*server.js", "*app.js", "*index.js", "*/routes/*.js", "*/handlers/*.js", "*/api/*.js"]
entrypoint_markers: ["http.createServer", "createServer(", "require('http')", "addEventListener('fetch'", "exports.handler"]
logic_layer_globs: ["*/services/*.js", "*/service/*.js", "*/models/*.js", "*/repositories/*.js", "*/dao/*.js", "*service*.js", "*model*.js"]
exported_symbol_patterns: ["^export ", "^module\\.exports", "exports\\.[A-Za-z]"]
---

# JavaScript Review Notes

## Attack Surface

Node is the usual runtime. This guide covers untrusted input beyond the web routes described by the
framework guides. A plain `http.createServer` callback, a serverless `exports.handler`, and a
`fetch` event listener are entrypoints too. Read the request body, query, params, headers, and
cookies as attacker-controlled.

## Trust Boundaries

JavaScript does not provide an application authorization boundary. Request and event data remain
untrusted until framework or application code binds them to an authenticated actor, tenant,
resource, and current operation.

## Review Guidance

### Common Sinks

- Command: `child_process.exec`, `execSync`, or `spawn` with a shell, built from
  input.
- Code: `eval`, `new Function`, `vm.runInContext` on input.
- SQL and NoSQL: a query built by string concatenation or template literal, and a
  Mongo query that takes a raw object from the body, the operator-injection sink.
- Path: `fs.readFile`, `path.join`, or `res.sendFile` on a path from input with no
  containment check.
- SSRF: `fetch`, `axios`, or `http.request` on a URL from input.
- Prototype pollution: a recursive merge or `lodash.merge` of a request body into
  an object, reaching prototype keys. Confirm the merge implementation and version
  actually permit prototype mutation before reporting `prototype-pollution`.

### Gotchas

- A missing `await` on an async auth check lets the handler proceed before it
  resolves.
- A regex from input, or a backtracking regex on input, is reportable as
  `resource-exhaustion` only when attacker-controlled input can force materially
  excessive work.
- `JSON.parse` of input into a wide model and assigning it whole is mass assignment.

## Safe Boundaries

JavaScript code is bounded when asynchronous authorization completes before the protected operation,
object binding excludes privileged fields and prototype keys, and query, code, command, path,
network, and regular expression operations constrain attacker input.
