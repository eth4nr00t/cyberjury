---
id: fastapi
title: FastAPI
kind: framework
language: python
detect:
  manifest: ["fastapi"]
  imports: ["from fastapi", "import fastapi"]
entrypoint_files: ["*main.py", "*/routers/*.py", "*/api/*.py", "*api.py", "*routes.py", "*/endpoints/*.py"]
entrypoint_markers: ["FastAPI(", "APIRouter(", "@app.get", "@app.post", "@router.get", "@router.post", "Depends("]
logic_layers: ["*/services/*.py", "*services.py", "*/models/*.py", "*models.py", "*/repositories/*.py", "*/crud/*.py", "*/dao/*.py"]
---
# FastAPI Review Notes

## Entrypoints
- Path operations decorated with `@app.get` / `@app.post` or `@router.*` on an
  `APIRouter`. Inputs arrive as path and query parameters, and as a request body
  validated by a Pydantic model.
- A Pydantic model bounds the body's shape, but an over-wide model still binds
  privileged fields, the mass-assignment shape.

## Authorization / IDOR
- Auth and access control run through `Depends`, for example a dependency that
  resolves the current user or checks a scope. Note an endpoint that omits the
  dependency its siblings use, or a dependency that authenticates but does not
  authorize the specific resource.
- IDOR: an endpoint that loads a record by an id parameter with no owner or tenant
  check.

## Common Sinks / Gotchas
- SQL: a raw query or an ORM `text()` built from a parameter.
- SSRF: `httpx` or `requests` to a URL from input, common in webhook and fetch
  endpoints.
- Path: `FileResponse` on a path from input.
- `CORSMiddleware` with `allow_origins=["*"]` together with credentials, and an
  OAuth2 bearer dependency that decodes a token without verifying signature,
  audience, and expiry.
