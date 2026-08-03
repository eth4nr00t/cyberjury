---
id: sql-injection
title: SQL Injection
lens: injection
impact: CRITICAL
tags: [cwe-89, owasp-a03, injection]
triggers: ["execute(", "executemany", ".raw(", "cursor", "SELECT ", "INSERT ", "f\"SELECT", "+ name", ".format(", "% (", "query ="]
---

# SQL Injection

Untrusted input concatenated or interpolated into a SQL statement lets an attacker change the query. Use parameterized queries / bound parameters. Never build SQL from input. Identifiers such as table and column names cannot be parameterized, so validate them against an allowlist.

## Python
Vulnerable:
```python
cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
```
Secure:
```python
cursor.execute("SELECT * FROM users WHERE name = %s", (name,))
```

## Java
Vulnerable: `stmt.executeQuery("SELECT * FROM u WHERE n='" + name + "'")`
Secure: `PreparedStatement ps = con.prepareStatement("... WHERE n=?"); ps.setString(1, name);`
