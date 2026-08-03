---
id: unrestricted-file-upload
title: Unrestricted File Upload
lens: unrestricted-file-upload
impact: HIGH
tags: [cwe-434, owasp-a04]
triggers: ["upload", "filename", ".save(", "multipart", "content-type", "secure_filename", "os.path.join", "MimeType"]
---

# Unrestricted File Upload

A handler that stores an uploaded file under an attacker-controlled name, extension, or
content type, into a web-served or executable directory, lets an attacker upload a
webshell such as a `.php` or `.jsp` file and execute it, or overwrite an existing file.
The boundary with path-traversal is the file type and execution, not the path: here the
danger is what the stored file is and where it can run. Force a safe generated name, an
allowlisted extension validated against the real content, and store outside the web root.

## Vulnerable
```python
@app.post("/upload")
def upload():
    f = request.files["file"]
    f.save(os.path.join(UPLOAD_DIR, f.filename))  # attacker sets name and extension
    return "ok"
```

## Secure
```python
ALLOWED = {"png", "jpg", "pdf"}


@app.post("/upload")
def upload():
    f = request.files["file"]
    ext = f.filename.rsplit(".", 1)[-1].lower()
    if ext not in ALLOWED:
        abort(400)
    name = f"{uuid4()}.{ext}"
    f.save(os.path.join(UPLOAD_DIR, name))  # generated name, allowlisted type, outside web root
    return "ok"
```

## Not a Finding

An upload validated against an extension and content-type allowlist, stored under a
generated name outside the web root, is the expected control. Report it only when the
name, extension, or type is attacker-controlled into a served or executable location, or
the validation is bypassable such as a check on the client-supplied content type alone.
