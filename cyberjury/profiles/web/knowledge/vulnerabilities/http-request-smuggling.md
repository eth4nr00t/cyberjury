---
id: http-request-smuggling
title: HTTP Request Smuggling
impact: HIGH
tags: [cwe-444, owasp-a03]
selection_hints: ["Content-Length", "Transfer-Encoding", "rawHeaders", "proxy_pass", "http-proxy", "proxy_request_buffering", "socket.on", "readSocket", "parseHeaders"]
---

# HTTP Request Smuggling

A front end proxy and a back end server disagree on where one request ends and the next begins, so
an attacker places a second request inside the first message. Conflicting framing headers and
noncanonical transfer encoding create different parser decisions. Report the proxy or parser where
the two hops select different body boundaries and show the downstream interpretation.

## Conflicting Framing Headers

Vulnerable:

```javascript
async function proxyRequest(req, socket, readExactly, forwardToUpstream) {
  const length = Number(req.headers["content-length"])
  const body = await readExactly(socket, length)
  forwardToUpstream(req, body)
}
```

Secure:

```javascript
async function proxyRequest(req, socket, readExactly, forwardToUpstream) {
  const hasCL = "content-length" in req.headers
  const hasTE = "transfer-encoding" in req.headers
  if (!hasCL || hasTE) {
    socket.destroy()
    return
  }
  const length = Number(req.headers["content-length"])
  const body = await readExactly(socket, length)
  forwardToUpstream(req, body)
}
```

This proxy implements only content length framing, so rejecting every transfer encoding value is
the controlling fact. A proxy that supports chunked bodies must instead parse and normalize them
without forwarding an ambiguous second framing signal.

## Transfer Encoding Normalization

Vulnerable:

```javascript
function forwardChunked(headers, rawBody, parseChunks, forward) {
  const transfer = headers["transfer-encoding"] || ""
  if (!transfer.toLowerCase().includes("chunked")) throw new Error("unsupported framing")
  const body = parseChunks(rawBody)
  return forward(headers, body)
}
```

Secure:

```javascript
function forwardChunked(headers, rawBody, parseChunks, forward) {
  const transfer = headers["transfer-encoding"]
  if (transfer !== "chunked" || "content-length" in headers) {
    throw new Error("ambiguous framing")
  }
  const body = parseChunks(rawBody)
  return forward({ "content-length": String(body.length) }, body)
}
```

The vulnerable parser accepts extra transfer coding tokens and forwards the original framing
header after changing the body. The secure parser accepts one canonical form and emits one framing
signal for the normalized body.

## Not a Finding

Request smuggling needs a real framing disagreement between two hops. A single conformant server
that rejects conflicting and noncanonical framing is not a finding. A proxy is also safe when it
parses one accepted form, removes the inbound framing headers, and emits one correct length for the
normalized body. Do not report header names alone without a parser or proxy path and a concrete
second interpretation.
