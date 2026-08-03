---
id: javascript
title: JavaScript
kind: language
detect:
  files: ["*.js", "*.mjs", "*.cjs", "*.jsx"]
entrypoint_files: ["*server.js", "*app.js", "*index.js", "*/routes/*.js", "*/handlers/*.js", "*/api/*.js"]
entrypoint_markers: ["http.createServer", "createServer(", "require('http')", "addEventListener('fetch'", "exports.handler"]
logic_layers: ["*/services/*.js", "*/service/*.js", "*/models/*.js", "*/repositories/*.js", "*/dao/*.js", "*service*.js", "*model*.js"]
api_patterns: ["^export ", "^module\\.exports", "exports\\.[A-Za-z]"]
---
# JavaScript Review Notes

Node is the usual runtime. Where untrusted input enters beyond web routes, which
the framework guides cover. A plain `http.createServer` callback, a serverless
`exports.handler`, and a `fetch` event listener are entrypoints too. Read the
request body, query, params, headers, and cookies as attacker-controlled.

## Common Sinks
- Command: `child_process.exec`, `execSync`, or `spawn` with a shell, built from
  input.
- Code: `eval`, `new Function`, `vm.runInContext` on input.
- SQL and NoSQL: a query built by string concatenation or template literal, and a
  Mongo query that takes a raw object from the body, the operator-injection sink.
- Path: `fs.readFile`, `path.join`, or `res.sendFile` on a path from input with no
  containment check.
- SSRF: `fetch`, `axios`, or `http.request` on a URL from input.
- Prototype pollution: a recursive merge or `lodash.merge` of a request body into
  an object, reaching `__proto__`.

## Gotchas
- A missing `await` on an async auth check lets the handler proceed before it
  resolves.
- A regex from input, or a catastrophic backtracking regex on input, is a ReDoS.
- `JSON.parse` of input into a wide model and assigning it whole is mass assignment.
