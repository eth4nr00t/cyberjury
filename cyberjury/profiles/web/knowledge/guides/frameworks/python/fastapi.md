---
id: fastapi
title: FastAPI
kind: framework
language: python
detect:
  manifest_hints: ["fastapi"]
  imports: ["from fastapi", "import fastapi"]
entrypoint_files: ["*/routers/*.py", "*/api/*.py", "*api.py", "*routes.py", "*/endpoints/*.py"]
entrypoint_markers: ["FastAPI(", "APIRouter(", "@app.get", "@app.post", "@router.get", "@router.post"]
logic_layer_files: ["*/models/*.py", "*models.py", "*/crud/*.py"]
public_api_patterns: []
---
# FastAPI Review Notes

## Entrypoints

- Path operations decorated with `@app.get` / `@app.post` or `@router.*` on an
  `APIRouter`. Inputs arrive as path and query parameters, and as a request body
  validated by a Pydantic model.
- A Pydantic model bounds the body's shape, but an over-wide model still binds
  privileged fields, the mass-assignment shape.

## Authorization and IDOR

- Auth and access control run through `Depends`, for example a dependency that
  resolves the current user or checks a scope. Note an endpoint that omits the
  dependency its siblings use, or a dependency that authenticates but does not
  authorize the specific resource.
- IDOR occurs when an endpoint loads a record by an id parameter with no owner or
  tenant check.

## Common Sinks and Gotchas

- SQL: a raw query or an ORM `text()` built from a parameter.
- SSRF: `httpx` or `requests` to a URL from input, common in webhook and fetch
  endpoints.
- Path: `FileResponse` on a path from input.
- CORS and OAuth2: `CORSMiddleware` with `allow_origins=["*"]` together with
  credentials, and a bearer dependency that decodes a token without verifying its
  signature, audience, and expiry.
  Report the CORS case only when a browser can read protected data or perform a
  protected action cross-origin. Configuration alone is not a finding.
