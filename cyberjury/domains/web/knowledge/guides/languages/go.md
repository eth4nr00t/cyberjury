---
id: go
title: Go
kind: language
detect:
  files: ["*.go", "go.mod"]
entrypoint_files: ["*main.go", "*/handlers/*.go", "*/handler/*.go", "*/api/*.go", "*/routes/*.go"]
entrypoint_markers: ["http.HandleFunc", "http.ListenAndServe", "ServeMux", "http.Handler", "func(w http.ResponseWriter"]
logic_layers: ["*/service/*.go", "*/services/*.go", "*/usecase/*.go", "*/repository/*.go", "*/repositories/*.go", "*/store/*.go", "*/dao/*.go", "*/model/*.go", "*/models/*.go"]
api_patterns: ["^func [A-Z]", "^func \\([^)]*\\) [A-Z]"]
---
# Go Review Notes

Where untrusted input enters beyond web routes, which the framework guides cover.
The standard `net/http` server is itself an entrypoint: a handler that takes an
`http.ResponseWriter` and an `*http.Request`, registered with `http.HandleFunc`
or a `ServeMux`. Read the request through `r.URL.Query`, `r.FormValue`, `r.PathValue`,
`r.Header`, and the decoded body, all attacker-controlled.

## Common Sinks
- SQL: a query built with `fmt.Sprintf` or string concatenation passed to
  `db.Query` or `db.Exec`. Use placeholders, never build SQL from input.
- Command: `exec.Command` with a shell or with arguments built from input,
  `os/exec` reaching `sh -c`.
- Path: `filepath.Join` or `os.Open` on a path from input with no `filepath.Clean`
  and containment check, the traversal sink.
- SSRF: `http.Get`, `http.NewRequest`, or a client `Do` on a URL from input.
- Deserialization and templates: `encoding/gob`, `text/template` rendering input,
  and `html/template` used with the wrong escaping context.

## Gotchas
- Some frameworks dispatch generic CRUD and its permission checks to a model or
  resource type rather than to the route, so the authorization decision and the
  response shape live in the logic layer, not the handler. Where that pattern is in
  use, audit each such method as an entrypoint: does the query scope to the caller's
  permission, and does the returned struct omit a secret field such as a token, a
  hash, or a password an unprivileged reader must not see?
- Errors ignored with `_` can skip a security check whose failure is never seen.
- A type assertion or `interface{}` body decoded with `json.Unmarshal` into a
  wide struct is mass assignment if privileged fields are bound.
- Goroutines and shared state without a lock are a race, relevant to one-time
  tokens and balances.
