---
id: oauth
title: OAuth and OIDC
kind: protocol
detect:
  content: ["grant_type", "authorization_code", "redirect_uri", "code_challenge", "response_type", "client_secret", "openid-configuration", "exchange_code"]
---
# OAuth and OIDC Review Notes

These are protocol invariants, independent of language or framework. The way each
check looks in code differs by stack, so read the language and framework guides
for the concrete idioms and confirm each invariant against the actual flow. An
OAuth or OIDC server holds protocol state, so the high-value bugs are logic,
authorization, and replay flaws rather than injection.

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

## Tokens and Sessions
- Access and refresh tokens are random, high entropy, scoped, and expiring.
- Refresh rotates and the previous token is revoked, so a captured refresh cannot
  be replayed.
- A JWT access token has its signature, algorithm, issuer, audience, and expiry
  verified. Disabling signature verification or allowing an unconstrained
  algorithm is a flaw. See the jwt-validation vulnerability class.

## Replay and Signatures
- A signed or one-time request such as an MFA binding, a webhook, or a privileged
  action carries a nonce or a short timestamp window and a single-use check, so a
  captured request cannot be replayed. See the replay-attack vulnerability class.

## Authorization per Endpoint
- Every token, introspection, revocation, and management endpoint authenticates
  the caller and authorizes the specific resource. Watch for an endpoint that
  acts on a client-supplied id with no owner or tenant check, the IDOR shape, and
  for a privileged endpoint left unauthenticated. See the
  insecure-direct-object-reference and missing-authorization vulnerability classes,
  and the Authorization Model step in the methodology.
