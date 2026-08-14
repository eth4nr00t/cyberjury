---
id: nosql-injection
title: NoSQL Injection
impact: HIGH
tags: [cwe-943, owasp-a03, injection]
selection_hints: ["findOne({", "find({", "collection.find", "collection.findOne", "mongoose", "MongoClient", "$where", "$ne", "$gt", "$regex", "where: req.body", "req.query.$"]
---

# NoSQL Injection

Passing untrusted input straight into a NoSQL query object lets an attacker inject query
operators rather than values. A login query can be bypassed when a password field arrives as
`{"$ne": null}`. Operators such as `$where`, `$gt`, and `$regex` can also extract or enumerate
data. The sql-injection class does not cover this because the payload is a structured operator,
not a string break. Report the query construction or database call where a raw request object
becomes query structure. Coerce each value to its expected scalar type or enforce a schema that
rejects operator objects before querying.

## Vulnerable
```javascript
async function authenticate(users, body) {
  return Boolean(await users.findOne({ user: body.user, pass: body.pass }))
}
```

## Secure
```javascript
async function authenticate(users, body) {
  if (typeof body.user !== "string" || typeof body.pass !== "string") {
    return false
  }
  return Boolean(await users.findOne({ user: body.user, pass: body.pass }))
}
```

## Not a Finding

A query whose untrusted fields are cast to their expected scalar type or validated against a
closed schema before the call has the expected control. An allowlisted server generated query
operator with attacker controlled scalar operands is also safe. Report only when a request value
can become query structure, such as a raw object, array, field name, or operator.
