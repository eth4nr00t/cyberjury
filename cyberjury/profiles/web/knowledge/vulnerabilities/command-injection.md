---
id: command-injection
title: Command Injection
impact: CRITICAL
tags: [cwe-78, owasp-a03, injection]
selection_hints: ["os.system", "os.popen", "subprocess.run", "subprocess.Popen", "shell=True", "Runtime.getRuntime().exec", "ProcessBuilder", "child_process.exec", "child_process.spawn", "child_process", "popen", "exec.Command"]
---

# Command Injection

## Security Condition

Command injection occurs when attacker input controls shell syntax, selects an executable outside a
closed set, or changes a fixed program's option semantics. The launched process then performs an
unintended command or privileged program action with the application's permissions, which can read
or modify data, execute code, or cross another system boundary.

## Review Guidance

Report the process launch where a request, stored value, or file metadata first gains that
authority. The required control depends on which command boundary the input crosses.

## Examples

### Shell Command Text

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

Removing the shell is the controlling fact. Character filtering around a shell string is not an
equivalent boundary.

### Executable Selection

Vulnerable:

```python
import subprocess


def run_report(payload):
    return subprocess.run([payload["program"]], check=True)
```

Secure:

```python
import subprocess


def run_report(payload):
    reports = {
        "disk": ["/usr/bin/df", "-h"],
        "memory": ["/usr/bin/free", "-m"],
    }
    return subprocess.run(reports[payload["report"]], shell=False, check=True)
```

The allowlist maps opaque operation names to server selected executable paths. Validating only the
shape of an attacker supplied path does not fix executable selection.

### Option Interpretation

Vulnerable:

```python
import subprocess


def archive(names):
    return subprocess.run(["tar", "-cf", "backup.tar", *names], shell=False, check=True)
```

Secure:

```python
import subprocess


def archive(names):
    return subprocess.run(["tar", "-cf", "backup.tar", "--", *names], shell=False, check=True)
```

The option terminator keeps an attacker supplied filename such as `--checkpoint-action=exec=...`
in the data portion of the argument list. Use this pattern only where the selected program defines
`--` as an option boundary.

## Not a Finding

A discrete argument list with no shell blocks shell metacharacters, but it is safe only when the
executable comes from trusted code and every attacker controlled argument remains data. A closed
operation map controls executable selection. Type validation or a documented option terminator can
control option semantics. Do not report a fixed executable whose attacker input cannot become an
option or a command, and do not treat character filtering as a substitute for removing a shell.
