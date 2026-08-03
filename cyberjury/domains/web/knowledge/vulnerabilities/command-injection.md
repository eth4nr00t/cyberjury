---
id: command-injection
title: Command Injection
lens: injection
impact: CRITICAL
tags: [cwe-78, owasp-a03, injection]
triggers: ["os.system", "os.popen", "subprocess", "shell=True", "Runtime.getRuntime", "child_process", "popen", "exec(", "exec.Command"]
---

# Command Injection

Passing untrusted input to a shell lets an attacker run arbitrary commands. Never build a shell string from input. Pass an argument list with the shell disabled.

## Python
Vulnerable:
```python
os.system("ping " + host)
subprocess.run(f"convert {name}", shell=True)
```
Secure:
```python
subprocess.run(["ping", "-c", "1", host], shell=False)
```

## Node.js
Vulnerable:
```javascript
child_process.exec(`ping ${host}`)
```
Secure:
```javascript
child_process.execFile("ping", ["-c", "1", host])
```

## Not a Finding

Command injection needs a shell to turn metacharacters into commands. An untrusted value
passed as a discrete argument to a program with no shell in the path is not injection, in any
language: Python `subprocess.run([...], shell=False)`, Node `execFile` or `spawn` without a
shell, Go `exec.Command(prog, args...)`. Report only when the input reaches a shell, such as
`os.system`, `shell=True`, or `child_process.exec`, or when the attacker controls the program
name or path itself, not just an argument to it.
