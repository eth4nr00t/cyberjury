---
id: typescript
title: TypeScript
kind: language
detect:
  files: ["*.ts", "*.tsx"]
entrypoint_files: ["*server.ts", "*app.ts", "*index.ts", "*/routes/*.ts", "*/handlers/*.ts", "*/api/*.ts"]
entrypoint_markers: ["http.createServer", "createServer(", "addEventListener('fetch'", "export const handler", "export async function handler"]
logic_layers: ["*/services/*.ts", "*/service/*.ts", "*/models/*.ts", "*/repositories/*.ts", "*/dao/*.ts", "*service*.ts", "*model*.ts"]
api_patterns: ["^export ", "^module\\.exports", "exports\\.[A-Za-z]"]
---
# TypeScript Review Notes

TypeScript runs as JavaScript on Node, so the JavaScript sinks and gotchas all
apply, read the JavaScript guide. The Node frameworks are shared, so an Express
or Nest service in TypeScript uses the same framework guides under
`frameworks/javascript`.

## What Types Do Not Protect
- Types are erased at runtime. A value typed as `string` is still attacker
  input, so type annotations do not sanitize a query, a path, or a command.
- A DTO typed in the code does not constrain the request body unless a runtime
  validator such as class-validator or zod actually enforces it, so an
  unvalidated body is still mass assignment.
- An `as` cast or `any` hides an untrusted value behind a safe-looking type.
- `JSON.parse` returns `any`, so a parsed body carries no real guarantees.

Beyond that, hunt the same sinks as JavaScript: command, code, SQL and NoSQL,
path traversal, SSRF, and prototype pollution.
