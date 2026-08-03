---
id: nosql-injection
title: NoSQL Injection
lens: injection
impact: HIGH
tags: [cwe-943, owasp-a03, injection]
triggers: ["find(", "findOne(", "$where", "$ne", "$gt", "req.body", "req.query", "collection.", "mongo"]
---

# NoSQL Injection

Passing untrusted input straight into a NoSQL query object lets an attacker inject query
operators rather than values. A login that builds `{ user, pass }` from the request body
is bypassed when `pass` arrives as `{"$ne": null}`, and `$where`, `$gt`, or `$regex`
extract or enumerate data. The sql-injection class does not cover this, the payload is a
structured operator, not a string break. Coerce inputs to the expected scalar type or
validate against a schema before querying.

## Vulnerable
```javascript
app.post("/login", (req, res) => {
  db.users.findOne({ user: req.body.user, pass: req.body.pass })   // pass can be {$ne: null}
    .then(u => res.json({ ok: !!u }))
})
```

## Secure
```javascript
app.post("/login", (req, res) => {
  const user = String(req.body.user)
  const pass = String(req.body.pass)   // operators cannot survive the cast to string
  db.users.findOne({ user, pass }).then(u => res.json({ ok: !!u }))
})
```

## Not a Finding

A query whose untrusted fields are cast to a scalar or validated against a schema before
the call is the expected control. Report it only when a request value reaches the query
object as a raw object or array, so an operator like `$ne`, `$gt`, `$regex`, or `$where`
can be injected.
