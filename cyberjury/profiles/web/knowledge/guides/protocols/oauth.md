---
id: oauth
title: OAuth and OIDC
kind: protocol
detect:
  content: ["grant_type", "authorization_code", "redirect_uri", "code_challenge", "response_type", "client_secret", "openid-configuration"]
entrypoint_files: []
entrypoint_markers: []
logic_layer_files: []
public_api_patterns: []
---
# OAuth and OIDC Review Notes

These are protocol invariants, independent of language or framework. The way each
check looks in code differs by stack, so read the language and framework guides
for the concrete idioms and confirm each invariant against the actual flow. An
OAuth or OIDC server holds protocol state, so the high-value bugs are logic,
authorization, and replay flaws rather than injection.

## Actors, Assets, and Trust Boundaries

- Actors include the resource owner, user agent, client, authorization server,
  OpenID provider, resource server, and an attacker controlling a browser or network
  endpoint. Public and confidential clients have different authentication abilities.
- Assets include authorization codes, access and refresh tokens, client credentials,
  user sessions, consent, identity claims, redirect destinations, and protected resources.
  Browser redirects, front-channel parameters, and public-client storage cross untrusted
  boundaries. Back-channel token requests are trusted only after endpoint and client
  authentication checks appropriate to the client type.

## State and Transitions

- Trace registration, authorization request, user authentication and consent, code issue,
  token exchange, resource access, refresh, revocation, logout, and expiry. Each transition
  accepts only the expected prior state and consumes one-time artifacts atomically.
- Bind an authorization transaction to the client, exact redirect URI, resource owner
  session, requested scope, PKCE challenge, and OIDC nonce where applicable. Do not accept
  a value from one transaction, issuer, tenant, or client in another.

## Authorization Code

- Single use. The code is redeemable once. The redeem path reads and marks the
  code consumed atomically, under a row lock or an equivalent conditional update,
  so two concurrent requests cannot both succeed. A read then update with no lock
  is a double-redeem.
- Bound to the client. A code issued to one client is rejected when another
  client presents it. The token step compares the code's client to the
  authenticated client.
- Bound to the redirect_uri and the PKCE verifier. Both at the token step match
  what was used at authorize. A missing PKCE check on a public client is
  exploitable.
- Expiry enforced. An expired code is rejected. Confirm the expiry is read and
  compared, not merely stored.

## Redirect URI and State

- redirect_uri is validated against a registered allowlist by exact match, not a
  prefix or a substring, so an open redirect or a code leak is not possible.
- A state or equivalent anti-forgery value is present and checked, to stop login
  CSRF.
- An OIDC client issues a fresh nonce and verifies the returned ID token nonce. State
  binds the browser transaction, while nonce binds the ID token and prevents replay.

## Tokens and Sessions

- Opaque tokens are random and high entropy. All token forms are scoped, audience-bound,
  and expiring. A signed token does not need to be random, but it still needs integrity
  and claim validation.
- Refresh tokens rotate or use an equivalent sender constraint and replay defense. When
  rotation is used, reuse of an old token revokes the affected token family or triggers
  another explicit containment action.
- A JWT access token has its signature, algorithm, issuer, audience, and expiry
  verified. Disabling signature verification or allowing an unconstrained
  algorithm is a flaw. See the jwt-validation vulnerability class.

## Replay, Expiry, and Revocation

- Authorization codes, OIDC nonces, and other one-time artifacts are rejected after use.
  Tokens and authorization sessions stop working at expiry. Refresh rotation detects reuse
  rather than silently issuing another access token. See the `replay-attack` vulnerability
  class.
- Revocation and logout invalidate the intended token, grant, and session scope. Confirm
  cached validation, long-lived sessions, and downstream resource servers observe the
  revocation behavior the design promises.

## Authorization per Endpoint

- Every token, introspection, revocation, and management endpoint applies the client
  authentication required for that client type and authorizes the specific resource.
  Watch for an endpoint that
  acts on a client-supplied id with no owner or tenant check, the IDOR shape, and
  for a privileged endpoint left unauthenticated. See the
  insecure-direct-object-reference and missing-authorization vulnerability classes,
  and the Authorization Model step in the methodology.

## Safe Boundaries

- A protocol parameter is safe only when it is verified against server-side transaction
  state and bound to the correct parties and artifact. Parsing a JWT, validating a redirect
  as a URL, or requiring a parameter does not establish those bindings.
- Report a concrete code, token, session, consent, or endpoint exploit. Do not report an
  optional hardening feature as a vulnerability when the deployed flow has an equivalent
  controlling fact.
