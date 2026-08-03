---
id: mcp
title: Model Context Protocol
kind: protocol
detect:
  content: ["modelcontextprotocol", "mcp.server", "fastmcp", "list_tools", "call_tool", "listtoolsrequestschema", "calltoolrequestschema", "@mcp.tool", "@mcp.resource", "@mcp.prompt", "setrequesthandler", "stdioservertransport", "sseservertransport", "streamablehttpservertransport", "tools/call", "resources/read"]
entrypoint_markers: ["@mcp.tool", "@mcp.resource", "@mcp.prompt", "@server.list_tools", "@server.call_tool", "list_tools", "call_tool", "CallToolRequestSchema", "ListToolsRequestSchema", "setRequestHandler", "FastMCP(", "Server("]
---
# Model Context Protocol Review Notes

These are protocol invariants, independent of language or framework. An MCP server
exposes a set of tools, resources, and prompts to a client and the model behind it,
so the high-value bugs are the classic ones reached through a new, often
unauthenticated, surface, plus one native to the protocol, indirect prompt
injection. Read the language and framework guides for the concrete SDK idioms, the
Python `fastmcp` and `mcp.server` decorators, the TypeScript `setRequestHandler`
handlers, and confirm each invariant against the actual tool implementations.

## Tool Arguments Are Untrusted Input
- A tool handler is an entrypoint. Its arguments arrive from the client and are
  influenced by the model, which is in turn steered by whatever content the model
  has read, so treat every argument as fully attacker-controlled, the same as an
  HTTP request body. A schema on the tool bounds the shape, not the values.
- A tool argument that reaches a shell, a subprocess, or an `exec` is the
  command-injection sink. See the command-injection and code-injection
  vulnerability classes.
- A tool argument used as a file path, joined onto a base directory or passed to
  open, read, or write, is the path-traversal sink. Confirm the path is confined
  to an allowed root by a check on the resolved path prefix, not a substring or a
  `startswith` on the unresolved string. See the path-traversal vulnerability class.
- A tool argument used as a URL for a server-side fetch is the SSRF sink. See the
  server-side-request-forgery vulnerability class.
- A tool argument that flows into a database query or an ORM raw call is the
  injection sink. See the sql-injection and nosql-injection vulnerability classes.
- A tool that binds its whole argument object onto a model or a record can set
  fields the caller should not control. See the mass-assignment vulnerability
  class.

## Authorization and Tenant Isolation
- A tool that performs a privileged action or reads a record from a
  caller-supplied id enforces its own authorization, it does not assume the client
  is trusted. Watch for a tool that acts on an id with no owner or tenant check,
  the IDOR shape, and for a privileged tool reachable with no authentication. See
  the insecure-direct-object-reference and missing-authorization vulnerability
  classes, and the Authorization Model step in the methodology.
- Judge authorization against the transport. A local `stdio` server that runs as
  the operator and only touches operator-owned resources is a different trust
  boundary from a remote `SSE` or streamable HTTP server reachable over the
  network. A remote transport that exposes tools with no authentication, or an
  OAuth proxy that forwards a token to an upstream without binding it to the
  caller, the confused deputy shape, is exploitable. See the
  improper-authentication vulnerability class.

## Indirect Prompt Injection
- A tool result, a resource body, or a prompt template that embeds untrusted
  external content, a fetched web page, a file, a database row, an issue comment,
  returns that content to the model as if it were trusted instruction. When the
  model can then call further tools that take real action, the external content
  steers those actions. Report it when untrusted external data reaches the model
  with no framing or separation and a capable tool is reachable downstream. See
  the prompt-injection vulnerability class.
- A tool or resource description built from untrusted or mutable external data is
  the tool poisoning shape, the description itself carries the injected
  instruction. See the prompt-injection vulnerability class.

## Not a Finding
- A local `stdio` tool whose arguments only ever resolve to constant or
  operator-supplied paths with no attacker influence is the expected design.
- A tool result returned to the model that contains only trusted, first-party data
  is not prompt injection.
- Report a tool surface only when a concrete argument or content flow reaches a
  real sink or a capable action. A tool that merely reads and displays first-party
  data with no downstream capability is not reportable on its own.
