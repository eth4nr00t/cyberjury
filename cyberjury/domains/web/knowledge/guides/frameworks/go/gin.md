---
id: gin
title: Gin
kind: framework
language: go
detect:
  manifest: ["gin-gonic/gin"]
  imports: ["github.com/gin-gonic/gin"]
entrypoint_files: ["*main.go", "*/handlers/*.go", "*/handler/*.go", "*/api/*.go", "*/routes/*.go", "*/controllers/*.go"]
entrypoint_markers: ["gin.Default(", "gin.New(", "*gin.Context", "router.GET", "router.POST", ".GET(", ".POST(", ".Group(", "c.Param", "c.Query", "c.ShouldBind"]
logic_layers: ["*/service/*.go", "*/services/*.go", "*/usecase/*.go", "*/repository/*.go", "*/repositories/*.go", "*/store/*.go", "*/dao/*.go", "*/model/*.go"]
---
# Gin Review Notes

## Entrypoints
- Handlers have the signature `func(c *gin.Context)`, registered with
  `router.GET`, `.POST`, and grouped under `router.Group`. Input comes from
  `c.Param`, `c.Query`, `c.PostForm`, `c.GetHeader`, and `c.ShouldBindJSON` or
  `c.Bind` into a struct.

## Authorization / IDOR
- Auth is middleware, applied globally, on a `Group`, or per route. The classic
  flaw is a route registered outside the authenticated group, so it inherits no
  check. Compare a group's routes against the routes registered on the bare
  engine.
- IDOR: a record loaded by `c.Param("id")` with no owner or tenant scope.

## Common Sinks / Gotchas
- SQL: `fmt.Sprintf` into `db.Query` or `db.Exec`, instead of placeholders.
- Command: `exec.Command` built from input.
- Path: `c.File` or `filepath.Join` on a path from input, the traversal sink.
- `c.ShouldBindJSON` into a struct with privileged fields is mass assignment.
- A handler that ignores the error from a bind or an auth call proceeds as if it
  passed.
