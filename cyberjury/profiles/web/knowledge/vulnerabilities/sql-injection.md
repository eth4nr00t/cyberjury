---
id: sql-injection
title: SQL Injection
impact: CRITICAL
tags: [cwe-89, owasp-a03, injection]
selection_hints: ["cursor.execute", "executemany", ".raw(", "text(f\"", "f\"SELECT", "f'SELECT", "db.Query(", "db.Exec(", "executeQuery(", "prepareStatement(", "query +="]
---

# SQL Injection

## Security Condition

Untrusted input that becomes SQL syntax lets an attacker change a query, read or modify data, bypass
authorization predicates, or invoke database capabilities. Data values and identifiers cross the
syntax boundary differently.

## Review Guidance

Report the execution call or construction line where attacker input gains control of SQL structure.

## Examples

### Data Values

Vulnerable:

```python
def find_user(cursor, name: str):
    return cursor.execute("SELECT * FROM users WHERE name = '" + name + "'").fetchone()
```

Secure:

```python
def find_user(cursor, name: str):
    return cursor.execute("SELECT * FROM users WHERE name = %s", (name,)).fetchone()
```

Use parameterized queries through the driver's parameter API for every attacker controlled data
value. Escaping or type checks do not replace binding when the value still enters statement text.

### Dynamic Identifiers

Vulnerable:

```python
def list_users(cursor, sort_field):
    return cursor.execute(f"SELECT id, name FROM users ORDER BY {sort_field}").fetchall()
```

Secure:

```python
def list_users(cursor, sort_field):
    columns = {"created": "created_at", "name": "name"}
    column = columns[sort_field]
    return cursor.execute(f"SELECT id, name FROM users ORDER BY {column}").fetchall()
```

Drivers generally cannot bind table names, column names, or sort directions. Map an opaque request
choice by exact match to a server selected SQL fragment.

## Not a Finding

A query is safe when every attacker controlled data value is bound through the driver's parameter
API and every dynamic identifier or sort direction is selected by exact match from a fixed map.
String escaping, quote replacement, numeric character checks, and ORM use are not substitutes for
binding when attacker input still reaches SQL syntax. An ORM query is safe only while values remain
data and no raw SQL construction reintroduces them as syntax.
