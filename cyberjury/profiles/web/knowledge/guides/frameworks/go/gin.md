---
id: gin
title: Gin
kind: framework
language: go
detect:
  manifest_hints: ["gin-gonic/gin"]
  imports: ["github.com/gin-gonic/gin"]
entrypoint_files: ["*/controllers/*.go"]
entrypoint_markers: ["*gin.Context", "router.GET", "router.POST", ".GET(", ".POST("]
logic_layer_files: []
public_api_patterns: []
---

# Gin Review Notes

## Attack Surface

### Entrypoints

- Handlers have the signature `func(c *gin.Context)`, registered with
  `router.GET`, `.POST`, and grouped under `router.Group`. Input comes from
  `c.Param`, `c.Query`, `c.PostForm`, `c.GetHeader`, and `c.ShouldBindJSON` or
  `c.Bind` into a struct.

## Trust Boundaries

### Authorization and IDOR

- Auth is middleware, applied globally, on a `Group`, or per route. The classic
  flaw is a route registered outside the authenticated group, so it inherits no
  check. Compare a group's routes against the routes registered on the bare
  engine.
- IDOR occurs when a record is loaded by `c.Param("id")` with no owner or tenant scope.

## Review Guidance

### Common Sinks and Gotchas

- SQL: `fmt.Sprintf` into `db.Query` or `db.Exec`, instead of placeholders.
- Command: `exec.Command` reaching a shell, using an attacker-selected executable,
  or passing an option that the fixed executable interprets as a dangerous action.
- Path: `c.File` or `filepath.Join` on a path from input, the traversal sink.
- Mass assignment: `c.ShouldBindJSON` into a struct with privileged fields.
- Error handling: a handler that ignores the error from a bind or an auth call proceeds
  as if it passed.

## Safe Boundaries

A Gin route is bounded when it belongs to the intended authenticated group, scopes resource access
to the verified owner or tenant, rejects bind failures, and confines each value before it reaches a
query, command, or file operation.
