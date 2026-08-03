---
id: echo
title: Echo
kind: framework
language: go
detect:
  manifest: ["labstack/echo"]
  imports: ["github.com/labstack/echo"]
entrypoint_files: ["*main.go", "*/handlers/*.go", "*/handler/*.go", "*/api/*.go", "*/routes/*.go", "*/controllers/*.go"]
entrypoint_markers: ["echo.New(", "echo.Context", "e.GET", "e.POST", ".GET(", ".POST(", ".Group(", "c.Param", "c.QueryParam", "c.Bind"]
logic_layers: ["*/service/*.go", "*/services/*.go", "*/usecase/*.go", "*/repository/*.go", "*/repositories/*.go", "*/store/*.go", "*/dao/*.go", "*/model/*.go"]
---
# Echo Review Notes

## Entrypoints
- Handlers have the signature `func(c echo.Context) error`, registered with
  `e.GET`, `.POST`, and grouped under `e.Group`. Input comes from `c.Param`,
  `c.QueryParam`, `c.FormValue`, `c.Request().Header`, and `c.Bind` into a struct.

## Authorization / IDOR
- Auth is middleware, applied globally, on a `Group`, or per route. The flaw to
  hunt is a route registered outside the authenticated group, inheriting no
  check. Compare grouped routes against routes on the bare instance.
- IDOR: a record loaded by `c.Param("id")` with no owner or tenant scope.

## Common Sinks / Gotchas
- SQL: `fmt.Sprintf` into `db.Query` or `db.Exec`, instead of placeholders.
- Command: `exec.Command` built from input.
- Path: `c.File` or `c.Attachment` and `filepath.Join` on a path from input.
- `c.Bind` into a struct with privileged fields is mass assignment.
- A returned `error` that the caller drops can hide a failed auth or validation.
