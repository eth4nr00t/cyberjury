---
id: prototype-pollution
title: Prototype Pollution
impact: HIGH
tags: [cwe-1321, owasp-a08]
selection_hints: ["__proto__", "constructor.prototype", "prototype pollution", "lodash.merge", "_.merge(", "deepmerge", "deepMerge(", "qs.parse", "set-by-path"]
---

# Prototype Pollution

A recursive merge, clone, or set by path operation that copies attacker controlled keys into a
JavaScript object without rejecting `__proto__`, `constructor`, or `prototype` writes onto
`Object.prototype`. Every object then inherits the injected property, which lets an
attacker tamper with application logic, cause denial of service, or in some sinks reach
remote code execution. Report the recursive assignment or library call where attacker selected
keys can reach a prototype. Reject those keys at every depth, use a null prototype object or a
`Map`, or enforce a closed schema before merging.

## Vulnerable
```javascript
function merge(target, source) {
  for (const key in source) {
    if (source[key] && typeof source[key] === "object") {
      merge(target[key] = target[key] || {}, source[key])
    } else {
      target[key] = source[key]
    }
  }
}

function parseOptions(body) {
  const options = {}
  merge(options, JSON.parse(body))
  return options
}
```

## Secure
```javascript
const BLOCKED = new Set(["__proto__", "constructor", "prototype"])
function merge(target, source) {
  for (const key of Object.keys(source)) {
    if (BLOCKED.has(key)) continue
    if (source[key] && typeof source[key] === "object") {
      merge(target[key] = target[key] || {}, source[key])
    } else {
      target[key] = source[key]
    }
  }
}

function parseOptions(body) {
  const options = Object.create(null)
  merge(options, JSON.parse(body))
  return options
}
```

## Not a Finding

The flow is safe when a closed schema rejects unexpected keys before assignment, dangerous keys
are rejected at every nesting depth, or attacker data remains in a `Map` or null prototype object
and never reaches a normal object's prototype. A shallow copy into a fresh object is not enough to
report without a concrete prototype write path. A library call is not reportable solely because an
old version was vulnerable. Report the in-repository flow, not a dependency advisory.
