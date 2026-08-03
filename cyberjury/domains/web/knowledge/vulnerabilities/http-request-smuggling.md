---
id: http-request-smuggling
title: HTTP Request Smuggling
lens: http-request-smuggling
impact: HIGH
tags: [cwe-444, owasp-a03]
triggers: ["Content-Length", "Transfer-Encoding", "chunked", "rawHeaders", "proxy_pass", "createServer", "socket.on", "readSocket", "upstream", "keep-alive", "HTTP/1.1", "parseHeaders"]
---

# HTTP Request Smuggling

A front-end proxy and a back-end server disagree on where one request ends and the next
begins, so an attacker smuggles a second request inside the body of the first. The
disagreement comes from a message that carries both `Content-Length` and
`Transfer-Encoding`, an accepted obsolete or malformed chunked encoding, or a custom
parser that frames the body differently from the upstream. The smuggled request poisons
the next victim's response, bypasses front-end authentication or path rules, or captures
the victim's request. Frame the body one way only, reject a message that carries both
`Content-Length` and `Transfer-Encoding`, reject malformed chunked encoding, and keep the
proxy and the origin on the same framing rules.

## Node
Vulnerable:
```javascript
// custom parser trusts Content-Length and ignores a conflicting Transfer-Encoding
const len = Number(req.headers["content-length"])
const body = await readExactly(socket, len)
forwardToUpstream(req, body)
```
Secure:
```javascript
const hasCL = "content-length" in req.headers
const hasTE = "transfer-encoding" in req.headers
if (hasCL && hasTE) {
    socket.destroy()
    return
}
```

## Not a Finding

Request smuggling needs a real framing disagreement between two hops, so a single server
on a standard, conformant HTTP stack that already rejects conflicting framing is not a
finding. Report it only when code parses the request body from raw bytes with its own
framing, forwards unvalidated framing headers to an upstream that frames differently, or
accepts both `Content-Length` and `Transfer-Encoding`. A reverse-proxy config that
forwards to one origin on a library that rejects ambiguous framing is not exploitable
without a concrete desync. Do not report this from the presence of header names alone
with no parser or proxy in the path.
