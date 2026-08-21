---
id: graphql
title: GraphQL
kind: protocol
detect:
  content: ["graphql", "GraphQLSchema", "buildSchema", "makeExecutableSchema", "ApolloServer", "typeDefs", "@Resolver", "resolveType", "introspection", "gql`"]
entrypoint_files: ["*resolvers.py", "*/resolvers/*.py", "*schema.py", "*.resolver.ts", "*.resolver.js", "*/resolvers/*.ts", "*/resolvers/*.js", "*subscription.py", "*subscriptions.py", "*/subscriptions/*.py", "*subscription.ts", "*subscriptions.ts", "*.subscription.ts", "*/subscriptions/*.ts", "*subscription.js", "*subscriptions.js", "*/subscriptions/*.js"]
entrypoint_markers: ["def resolve_", "resolve_reference", "graphene.ObjectType", "@strawberry.field", "strawberry.type", "@Resolver(", "@ResolveField(", "@FieldResolver(", ".set_field(", "type Subscription", "@Subscription(", "@strawberry.subscription", "SubscriptionType(", "asyncIterator(", "subscribe:"]
logic_layer_files: []
public_api_patterns: []
---

# GraphQL Review Notes

## Attack Surface

These are protocol invariants, independent of language or framework. A GraphQL endpoint exposes one
transport over many operations, so the high-value bugs are authorization and business-logic flaws at
the resolver, not injection at the transport. Read the language and framework guides for the
concrete resolver idioms and confirm each invariant against the actual schema and resolvers.

## Trust Boundaries

### Actors, Assets, and Trust Boundaries

- Actors include anonymous callers, authenticated users, administrators, service
  accounts, resolver code, data loaders, backing services, and subscription brokers.
  Assets include object fields, mutation authority, tenant boundaries, credentials,
  and backend capacity.
- The transport, operation document, variables, aliases, global ids, and subscription
  filters are attacker-controlled. Authentication context, server-side policy, and
  tenant-scoped data access are trusted only after the resolver verifies how they were
  derived and where they are applied.

### State and Lifecycle

- A query or mutation moves from parse and validation through resolver execution to a
  response. Authorization must hold at each resolver that reads or changes an asset.
  A check on an earlier resolver does not bind a later nested resolver.
- A subscription adds connection, authentication, subscribe, event delivery, and
  disconnect states. Bind the subscriber identity, tenant, operation, and variables to
  the live subscription. Recheck permission when each event is read or delivered.
- Expired or revoked sessions and credentials must stop new operations and terminate or
  reauthorize long-lived subscriptions. A reconnect, reused operation id, or replayed
  subscription message must not restore authority or duplicate a state-changing action.

## Review Guidance

### Authorization per Resolver

- Authorization is enforced per field and per resolver, not only at the HTTP layer. A
  single authenticated query can reach many resolvers, so a check on the entry mutation
  does not protect a nested field. Watch for a resolver that reads or writes a record
  from a client-supplied id with no owner or tenant check, the IDOR shape, and for a
  privileged field reachable by any authenticated caller. See the
  insecure-direct-object-reference and missing-authorization vulnerability classes, and
  the authorization model in repository context.
- Node-style global ids decode to a type and a database id. Confirm the resolver
  re-checks ownership after decoding, since the id is attacker-supplied.

### Mutations and Input

- A mutation that binds an input object straight onto a model can set fields the caller
  should not control, such as a role, an owner, or a balance. See the mass-assignment
  vulnerability class.
- A resolver argument flows into a database query, a shell command, or a template the
  same way any untrusted input does. See the sql-injection, nosql-injection, and
  command-injection vulnerability classes.

### Subscriptions

- A subscription reads records and pushes them to the subscriber, so it is a read path and
  carries the same authorization duty as a query. It rarely carries the same code. A
  subscription runs outside the per-request pipeline, driven by an event rather than by the
  caller's request, so the caller's identity and permission context is the thing most easily
  dropped on the way. Read how the subscription obtains its data access object and compare it
  with the query path on the same collection: where the query passes the caller's identity,
  permissions, or tenant, and the subscription constructs its reader with only a schema or a
  connection, the subscription returns records the caller cannot read. A low-privilege
  subscriber then receives create and update events, field values included, for records the
  query path would have filtered out. See the missing-authorization and
  insecure-direct-object-reference vulnerability classes.
- The subscribe step and the resolve step are separate. A check on subscribe runs once at
  connect time, so it cannot enforce anything about the records each later event carries.
  Confirm the per-event read is filtered, not just the initial connection authenticated.
- A subscription filter argument that selects which events a client receives is a filter, not
  a control. Confirm the server also enforces what that client may see, or a client widens
  its own filter and receives everything.

### Introspection and Schema Exposure

- Introspection enabled on a production endpoint maps the whole schema, including
  internal types and admin mutations. Report it as a finding only when it exposes a
  concrete privileged surface that lacks its own authorization, not on its own.

### Query Cost

- A deeply nested or cyclic query, an unbounded list field, or batched and aliased
  operations in one request amplify backend work. Confirm a depth limit, a complexity or
  cost limit, and a cap on batching or aliasing bound the work. A missing limit that lets
  one request force heavy, repeated backend work is a `resource-exhaustion` finding, not a
  bare best-practice note. See that vulnerability class and the
  methodology for the impact bar.

### Batching and Aliasing as a Control Bypass

- Query batching and field aliasing pack many operations into one HTTP request, so a
  per-request throttle or a per-request anti-automation check is applied once while the
  server runs every operation. When the throttled operation is a credential, OTP, or
  two-factor check, this is an authentication bypass, not a rate-limit note, since one
  request brute-forces the secret. Confirm the limit counts operations, not requests, on
  any verification path. See the improper-authentication vulnerability class.

### Requests and CSRF

- A mutation reachable over `GET`, or a server that accepts a mutation with a simple
  content type such as `application/x-www-form-urlencoded`, `multipart/form-data`, or
  `text/plain`, is forgeable cross-site, since the request needs no preflight and rides
  the victim's cookie session. Confirm state-changing operations require `POST` with a
  JSON content type, or a CSRF token, or a non-cookie credential such as a bearer token.
  See the cross-site-request-forgery vulnerability class.

## Safe Boundaries

- Schema validation and static types bound shape, not authorization. A resolver is safe
  when its data access is scoped to the verified caller and tenant, its state transition
  enforces the current object state, and any downstream sink applies its own required
  control.
- Introspection, batching, aliases, or subscriptions are not findings by themselves.
  Report only the concrete authorization bypass, replay, cross-site state change, or
  resource impact they make exploitable.
