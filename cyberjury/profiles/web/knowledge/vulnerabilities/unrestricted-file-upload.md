---
id: unrestricted-file-upload
title: Unrestricted File Upload
impact: HIGH
tags: [cwe-434, owasp-a04]
selection_hints: ["UploadFile", "multipart/form-data", "FileStorage", "multer(", "busboy", "upload.single(", "secure_filename", "allowed_extensions", "getContentType("]
---

# Unrestricted File Upload

## Security Condition

A handler that stores an uploaded file under an attacker-controlled name, extension, or content
type, into a web served or executable directory, lets an attacker upload a webshell such as a `.php`
or `.jsp` file and execute it, or overwrite an existing file. The boundary with path traversal is
the file type and execution, not the path. Here the danger is what the stored file is and where it
can run. Force a safe generated name and either validate the real content against an allowlist or
store it as inert data outside the web root.

## Review Guidance

Report the write location where attacker controlled content can become executable or replace a
sensitive file. An upload that only causes inert, isolated storage consumption belongs in resource
exhaustion when a concrete outage is possible.

## Examples

### Executable Upload Storage

Vulnerable:

```python
from pathlib import Path

WEB_ROOT = Path("/srv/www/uploads")


def store_upload(filename: str, content: bytes) -> Path:
    target = WEB_ROOT / filename
    target.write_bytes(content)
    return target
```

Secure:

```python
import secrets
from pathlib import Path

DATA_DIR = Path("/srv/app-data/uploads")


def store_inert_upload(content: bytes) -> Path:
    target = DATA_DIR / f"{secrets.token_hex(16)}.bin"
    target.write_bytes(content)
    return target
```

## Not a Finding

An upload is safe for this class when it is stored under a generated name outside every served or
executable path and never passed to an interpreter. A service that must serve or process uploads
also needs a real decoder or validator for its allowed formats and must return content as inert
data. Size bounds remain necessary against resource exhaustion, but they do not control executable
upload behavior. A filename sanitizer prevents traversal but does not prevent executable content. A
client supplied content type or filename extension is not content validation. Report only when
attacker controlled content can reach a served or executable location or overwrite a sensitive
path.
