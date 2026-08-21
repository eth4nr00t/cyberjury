---
id: typescript
title: TypeScript
kind: language
detect:
  files: ["*.ts", "*.tsx", "*.mts", "*.cts"]
entrypoint_globs: ["*server.ts", "*app.ts", "*index.ts", "*/routes/*.ts", "*/handlers/*.ts", "*/api/*.ts"]
entrypoint_markers: ["http.createServer", "createServer(", "addEventListener('fetch'", "export const handler", "export async function handler"]
logic_layer_globs: ["*/services/*.ts", "*/service/*.ts", "*/models/*.ts", "*/repositories/*.ts", "*/dao/*.ts", "*service*.ts", "*model*.ts"]
exported_symbol_patterns: ["^export ", "^module\\.exports", "exports\\.[A-Za-z]"]
---

# TypeScript Review Notes

## Attack Surface

TypeScript runs as JavaScript on Node, so the JavaScript sinks and gotchas all apply. The Node
frameworks are shared, so an Express or NestJS service in TypeScript uses a framework guide under the
guide's declared language. This guide remains self-contained because selecting TypeScript does not
imply that the JavaScript guide is also selected.

## Trust Boundaries

TypeScript types do not establish an application authorization or runtime validation boundary.
Values remain untrusted after compilation until framework or application code binds them to an
authenticated actor and enforces their runtime shape and authority.

## Review Guidance

### What Types Do Not Protect

- Types are erased at runtime. A value typed as `string` is still attacker
  input, so type annotations do not sanitize a query, a path, or a command.
- A DTO typed in the code does not constrain the request body unless a runtime
  validator such as class-validator or zod actually enforces it, so an
  unvalidated body is still mass assignment.
- An `as` cast or `any` hides an untrusted value behind a safe-looking type.
- `JSON.parse` returns `any`, so a parsed body carries no real guarantees.

### Common Sinks

- Command and code execution: `child_process.exec`, `execSync`, a shell-enabled
  `spawn`, `eval`, `new Function`, and `vm` execution on attacker input. See the
  `command-injection` and `code-injection` vulnerability classes.
- SQL and NoSQL: string-built queries, unsafe raw ORM calls, and raw request objects
  used as Mongo filters. See `sql-injection` and `nosql-injection`.
- Files and network: `fs` operations on an unconfined path and `fetch`, `axios`, or
  `http.request` on an attacker-selected URL. See `path-traversal` and
  `server-side-request-forgery`.
- Object and template operations: recursive merges that permit prototype keys and
  rendering attacker input as a template. See `prototype-pollution`,
  `cross-site-scripting`, and `server-side-template-injection` as the output context
  requires.

### Async and Runtime Gotchas

- A missing `await` on an asynchronous authentication or authorization check can let
  the protected operation run before the decision completes.
- A rejected promise caught by a broad handler can become an allow path when the
  code continues with a default user or permission result.
- A regular expression is a `resource-exhaustion` issue only when attacker input can
  force materially excessive work.

## Safe Boundaries

TypeScript code is bounded when runtime validation permits only intended fields, awaited
authorization completes before the protected operation, and the emitted JavaScript constrains query,
code, command, object, file, network, and template inputs.
