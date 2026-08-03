# Vulnerability Class Index

Application-security vulnerability classes, one file per weakness under
`vulnerabilities/`, named by the specific weakness, CWE-style. Each states impact,
the markers to hunt in `triggers`, and vulnerable-vs-secure examples. The
diff-audit engine injects the classes relevant to a change into the prompt. The
repository-review agent reads them for the target's stack. A finding's `category` is one
of these ids.

## Vulnerability Classes by OWASP Category

### A01 Broken Access Control
- `missing-authorization` CWE-862
- `insecure-direct-object-reference` CWE-639
- `cross-site-request-forgery` CWE-352
- `path-traversal` CWE-22
- `open-redirect` CWE-601

### A02 Cryptographic Failures
- `insecure-cryptography` CWE-327
- `insecure-transport` CWE-319
- `hardcoded-secrets` CWE-798
- `information-exposure` CWE-200/532

### A03 Injection
- `sql-injection` CWE-89
- `command-injection` CWE-78
- `code-injection` CWE-94
- `cross-site-scripting` CWE-79
- `xml-external-entity` CWE-611
- `server-side-template-injection` CWE-1336
- `http-response-splitting` CWE-113
- `http-request-smuggling` CWE-444
- `nosql-injection` CWE-943
- `prompt-injection` CWE-1427

### A04 Insecure Design / Business Logic
- `business-logic` CWE-840
- `replay-attack` CWE-294
- `race-condition` CWE-362
- `mass-assignment` CWE-915
- `unrestricted-file-upload` CWE-434
- `resource-exhaustion` CWE-400/1333/770

### A05 Security Misconfiguration
- `cors-misconfiguration` CWE-942
- `security-misconfiguration` CWE-16

### A07 Identification and Authentication
- `improper-authentication` CWE-287
- `jwt-validation` CWE-347
- `insecure-session-management` CWE-384/613/614

### A08 Software and Data Integrity
- `insecure-deserialization` CWE-502
- `prototype-pollution` CWE-1321

### A10 Server-Side Request Forgery
- `server-side-request-forgery` CWE-918

Report only real, exploitable, high-confidence issues with a concrete exploit
path. Do not report dependency CVEs, style, speculation, or config-leak-only
risks. The set is data: add a class by dropping a new `vulnerabilities/<id>.md`
with the same frontmatter of id, title, impact, tags, triggers, and lens, plus examples.
