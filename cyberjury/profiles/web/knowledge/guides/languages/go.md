---
id: go
title: Go
kind: language
detect:
  files: ["*.go", "go.mod"]
entrypoint_files: ["*main.go", "*/handlers/*.go", "*/handler/*.go", "*/api/*.go", "*/routes/*.go"]
entrypoint_markers: ["http.HandleFunc", "http.ListenAndServe", "ServeMux", "http.Handler", "func(w http.ResponseWriter"]
logic_layer_files: ["*/service/*.go", "*/services/*.go", "*/usecase/*.go", "*/repository/*.go", "*/repositories/*.go", "*/store/*.go", "*/dao/*.go", "*/model/*.go", "*/models/*.go"]
public_api_patterns: ["^func [A-Z]", "^func \\([^)]*\\) [A-Z]"]
---

# Go Review Notes

## Attack Surface

This guide covers untrusted input beyond the web routes described by the framework guides. The
standard `net/http` server is itself an entrypoint: a handler that takes an `http.ResponseWriter`
and an `*http.Request`, registered with `http.HandleFunc` or a `ServeMux`. Read the request through
`r.URL.Query`, `r.FormValue`, `r.PathValue`, `r.Header`, and the decoded body, all
attacker-controlled.

## Trust Boundaries

Go does not provide an application authorization boundary. Treat a value as trusted only after the
selected framework or application code binds it to an authenticated actor, tenant, resource, and
current operation.

## Review Guidance

### Common Sinks

- SQL: a query built with `fmt.Sprintf` or string concatenation passed to
  `db.Query` or `db.Exec`. Use placeholders, never build SQL from input.
- Command: `os/exec` reaching a shell such as `sh -c`, or attacker control of the
  executable name. Attacker-controlled arguments to a fixed executable need a
  concrete option or argument injection path. They are not shell injection by default.
- Path: `filepath.Join` or `os.Open` on a path from input with no `filepath.Clean`
  and containment check, the traversal sink.
- SSRF: `http.Get`, `http.NewRequest`, or a client `Do` on a URL from input.
- Deserialization and templates: `encoding/gob`, `text/template` rendering input,
  and `html/template` used with the wrong escaping context. Treat a decoder as a
  security sink only when attacker input can consume unbounded resources, populate
  security-sensitive state, or reach a dangerous operation.

### Gotchas

- Some frameworks dispatch generic CRUD and its permission checks to a model or
  resource type rather than to the route, so the authorization decision and the
  response shape live in the logic layer, not the handler. Where that pattern is in
  use, audit each such method as an entrypoint: does the query scope to the caller's
  permission, and does the returned struct omit a secret field such as a token, a
  hash, or a password an unprivileged reader must not see?
- Errors ignored with `_` can skip a security check whose failure is never seen.
- A type assertion or `interface{}` body decoded with `json.Unmarshal` into a
  wide struct is mass assignment if privileged fields are bound.
- Shared state without synchronization is security relevant when a concurrent
  attacker can violate an invariant, such as redeeming a one-time token twice or
  applying the same balance update twice. See the `race-condition` and
  `replay-attack` vulnerability classes.

## Safe Boundaries

Go code is bounded when authorization errors are handled, resource access uses verified actor or
tenant scope, concurrent state transitions preserve their invariant, and query, command, path,
network, decoder, and template APIs receive constrained values.
