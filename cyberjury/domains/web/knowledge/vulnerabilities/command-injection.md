---
id: command-injection
title: Command Injection
impact: CRITICAL
tags: [cwe-78, owasp-a03, injection]
selection_hints: ["os.system", "os.popen", "subprocess.run", "subprocess.Popen", "shell=True", "Runtime.getRuntime().exec", "ProcessBuilder", "child_process.exec", "child_process.spawn", "child_process", "popen", "exec.Command"]
---

# Command Injection

Passing attacker controlled input to a shell command string lets the attacker use metacharacters
or substitutions to run additional commands with the application's permissions. An attacker can
also select the executable or supply an option that makes a fixed executable perform an unintended
dangerous operation. Report the process launch where a request, stored attacker value, or file
metadata controls the command text, executable, or security-sensitive option semantics. Never
build a shell string from input. Use a fixed executable with the shell disabled, then validate
arguments as data or terminate option parsing where the program supports it.

## Python

Vulnerable:

```python
import subprocess


def ping(host):
    return subprocess.run("ping -c 1 " + host, shell=True, check=True)
```

Secure:

```python
import ipaddress
import subprocess


def ping(host):
    address = str(ipaddress.ip_address(host))
    return subprocess.run(["ping", "-c", "1", address], shell=False, check=True)
```

## Node.js

Vulnerable:

```javascript
function ping(childProcess, host) {
  return childProcess.exec(`ping ${host}`)
}
```

Secure:

```javascript
import net from "node:net"

function ping(childProcess, host) {
  if (!net.isIP(host)) throw new Error("IP address required")
  return childProcess.execFile("ping", ["-c", "1", host])
}
```

## Go

Vulnerable:

```go
package example

import "os/exec"

func ping(host string) error {
	return exec.Command("sh", "-c", "ping -c 1 "+host).Run()
}
```

Secure:

```go
package example

import (
	"errors"
	"net"
	"os/exec"
)

func ping(host string) error {
	if net.ParseIP(host) == nil {
		return errors.New("IP address required")
	}
	return exec.Command("ping", "-c", "1", host).Run()
}
```

## Not a Finding

A discrete argument list with no shell blocks shell metacharacters. It is safe when the
executable is fixed and each attacker controlled argument is treated only as data, for example
after type validation or an option terminator. Report when input reaches a shell such as
`os.system`, `shell=True`, or `child_process.exec`, when the attacker controls the executable,
or when a user argument can be parsed as a dangerous option by the fixed executable. Character
validation is not a substitute for removing the shell when a fixed program and argument list can
perform the task.
