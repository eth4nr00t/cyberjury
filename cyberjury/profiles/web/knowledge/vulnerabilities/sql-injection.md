---
id: sql-injection
title: SQL Injection
impact: CRITICAL
tags: [cwe-89, owasp-a03, injection]
selection_hints: ["cursor.execute", "executemany", ".raw(", "text(f\"", "f\"SELECT", "f'SELECT", "db.Query(", "db.Exec(", "executeQuery(", "prepareStatement(", "query +="]
---

# SQL Injection

Untrusted input concatenated or interpolated into a SQL statement lets an attacker change the
query, read or modify data, bypass authorization predicates, or invoke database capabilities.
Report the query execution call or construction line where attacker controlled data becomes SQL
syntax. Use parameterized queries and bind data values through the driver's parameter API.
Identifiers such as table and column
names usually cannot be bound, so map them by exact match to server selected identifiers.

## Python

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

## JavaScript and TypeScript

Vulnerable:

```javascript
async function findUser(database, name) {
  return database.query(`SELECT * FROM users WHERE name = '${name}'`)
}
```

Secure:

```javascript
async function findUser(database, name) {
  return database.query("SELECT * FROM users WHERE name = $1", [name])
}
```

## Go

Vulnerable:

```go
package users

import (
	"database/sql"
	"fmt"
)

func Find(database *sql.DB, name string) (*sql.Rows, error) {
	query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
	return database.Query(query)
}
```

Secure:

```go
package users

import "database/sql"

func Find(database *sql.DB, name string) (*sql.Rows, error) {
	return database.Query("SELECT * FROM users WHERE name = ?", name)
}
```

## Not a Finding

A query is safe when every attacker controlled data value is bound through the driver's parameter
API and any dynamic identifier or sort direction is selected by exact match from a fixed allowlist.
String escaping, quote replacement, numeric character checks, and ORM use are not substitutes for
binding when attacker input still reaches SQL syntax. An ORM query is safe only while values remain
data and no raw SQL construction reintroduces them as syntax.
