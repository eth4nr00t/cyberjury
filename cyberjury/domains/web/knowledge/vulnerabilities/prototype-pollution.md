---
id: prototype-pollution
title: Prototype Pollution
lens: deserialization
impact: HIGH
tags: [cwe-1321, owasp-a08]
triggers: ["__proto__", "constructor", "prototype", "merge", "Object.assign", "deepMerge", "[key]", "extend("]
---

# Prototype Pollution

A recursive merge, clone, or `set`-by-path that copies attacker-controlled keys into a
JavaScript object without rejecting `__proto__`, `constructor`, or `prototype` writes onto
`Object.prototype`. Every object then inherits the injected property, which lets an
attacker tamper with application logic, cause denial of service, or in some sinks reach
remote code execution. Reject those keys, use a null-prototype object or a `Map`, or
validate against a schema before merging.

## Vulnerable
```javascript
function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === "object") {
      merge(target[key] = target[key] || {}, source[key])   // walks __proto__ from user JSON
    } else {
      target[key] = source[key]
    }
  }
}
merge({}, JSON.parse(req.body))
```

## Secure
```javascript
const BLOCKED = new Set(["__proto__", "constructor", "prototype"])
function merge(target, source) {
  for (const key in source) {
    if (BLOCKED.has(key)) continue
    if (typeof source[key] === "object") {
      merge(target[key] = target[key] || {}, source[key])
    } else {
      target[key] = source[key]
    }
  }
}
```
