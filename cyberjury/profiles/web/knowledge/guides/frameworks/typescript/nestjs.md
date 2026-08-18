---
id: nestjs
title: NestJS
kind: framework
language: typescript
detect:
  manifest_hints: ["@nestjs/core", "@nestjs/common"]
  imports: ["@nestjs/common", "@nestjs/core"]
entrypoint_files: ["*.controller.ts", "*.controller.js", "*/controllers/*.ts", "*.resolver.ts", "*.gateway.ts"]
entrypoint_markers: ["@Controller(", "@Get(", "@Post(", "@Put(", "@Patch(", "@Delete(", "@Resolver(", "@Query(", "@Mutation(", "@SubscribeMessage("]
logic_layer_files: ["*.service.ts", "*.repository.ts", "*.entity.ts"]
public_api_patterns: []
---
# NestJS Review Notes

Usually TypeScript on Node. See the JavaScript and TypeScript guides for the
runtime sinks and for why types do not sanitize input.

## Entrypoints

- A `@Controller` class with `@Get` / `@Post` methods. Input binds through
  `@Param`, `@Query`, `@Body`, and `@Headers`. GraphQL resolvers and WebSocket
  gateways are entrypoints too.

## Authorization and IDOR

- Access control is a guard applied with `@UseGuards`, at the controller or the
  method, plus role decorators. The flaw to hunt is a route or controller missing
  the guard its siblings declare, and a guard that authenticates but does not
  authorize the specific resource.
- IDOR occurs when a handler loads by `@Param("id")` with no owner or tenant check.

## Common Sinks and Gotchas

- Mass assignment: a `@Body` DTO with no `ValidationPipe` and `whitelist: true`
  binds any field the client sends. Confirm the pipe is global or applied.
- SQL: a TypeORM or Prisma raw query built from input.
- SSRF: a server-side `fetch` or `axios` to a URL from input.
- Guard behavior: a custom guard returns true on an unhandled path or reads the user
  from a header the client controls.
