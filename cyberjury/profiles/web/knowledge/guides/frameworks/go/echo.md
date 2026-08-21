---
id: echo
title: Echo
kind: framework
language: go
detect:
  manifest_hints: ["labstack/echo"]
  imports: ["github.com/labstack/echo"]
entrypoint_files: ["*/controllers/*.go"]
entrypoint_markers: ["echo.Context", "e.GET", "e.POST", ".GET(", ".POST("]
logic_layer_files: []
public_api_patterns: []
---

# Echo Review Notes

## Attack Surface

### Entrypoints

- Handlers have the signature `func(c echo.Context) error`, registered with
  `e.GET`, `.POST`, and grouped under `e.Group`. Input comes from `c.Param`,
  `c.QueryParam`, `c.FormValue`, `c.Request().Header`, and `c.Bind` into a struct.

## Trust Boundaries

### Authorization and IDOR

- Auth is middleware, applied globally, on a `Group`, or per route. The flaw to
  hunt is a route registered outside the authenticated group, inheriting no
  check. Compare grouped routes against routes on the bare instance.
- IDOR occurs when a record is loaded by `c.Param("id")` with no owner or tenant scope.

## Review Guidance

### Common Sinks and Gotchas

- SQL: `fmt.Sprintf` into `db.Query` or `db.Exec`, instead of placeholders.
- Command: `exec.Command` reaching a shell, using an attacker-selected executable,
  or passing an option that the fixed executable interprets as a dangerous action.
- Path: `c.File` or `c.Attachment` and `filepath.Join` on a path from input.
- Mass assignment: `c.Bind` into a struct with privileged fields.
- Error handling: a returned `error` that the caller drops can hide a failed auth or
  validation.

## Safe Boundaries

An Echo route is bounded when it inherits the intended authentication middleware, scopes resource
access to the verified owner or tenant, validates bound fields, and confines each value before it
reaches a query, command, or file operation.
