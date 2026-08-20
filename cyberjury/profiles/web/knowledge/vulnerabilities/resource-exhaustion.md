---
id: resource-exhaustion
title: Uncontrolled Resource Consumption
impact: HIGH
tags: [cwe-400, cwe-1333, cwe-770, owasp-a04]
selection_hints: ["re.compile", "re.match", "re.search", "new RegExp", "catastrophic backtracking", "extractall", "ZipFile", "decompress(", "gzip.GzipFile", "range(int(", "ET.fromstring", "make([]byte", "MAX_CONTENT_LENGTH"]
---

# Uncontrolled Resource Consumption

One request, or a few, exhausts a server resource and takes the service down. Common forms include
catastrophic regex backtracking, attacker sized allocations or loops, and archive or parser
expansion without a bound. Trace attacker control to the regex, allocation, loop, decompressor, or
parser and report that operation when it can deny service. Bound the work before it starts through
safe patterns, execution limits, size and count limits, or capped decompressed output.

## Regex Backtracking

Regex denial of service has two distinct input paths. A fixed application pattern may contain
ambiguous repetition and run against attacker controlled text. An attacker may instead supply or
persist a pattern that later runs against sufficiently large text. A short pattern is not safe by
length alone because nested quantifiers can cause exponential work in a few characters.

### Python

Vulnerable fixed pattern:

```python
import re


def valid_query(query: str) -> bool:
    return re.match(r"^(\w+\s?)*$", query) is not None
```

Secure fixed pattern:

```python
import re


def valid_query(query: str) -> bool:
    return len(query) <= 256 and re.fullmatch(r"\w[\w ]{0,255}", query) is not None
```

Vulnerable supplied pattern:

```python
import re


def search_logs(user_pattern: str, log_lines: list[str]) -> list[str]:
    pattern = re.compile(user_pattern)
    return [line for line in log_lines if pattern.search(line)]
```

Secure supplied pattern:

```python
import re


SAFE_PATTERNS = {"error": re.compile(r"^ERROR:"), "warning": re.compile(r"^WARNING:")}


def search_logs(mode: str, log_lines: list[str]) -> list[str]:
    pattern = SAFE_PATTERNS.get(mode)
    return [line for line in log_lines if pattern and pattern.search(line)]
```

Trace API, deserializer, serializer, or database writes into regex compilation and execution.
Confirm that the actor can trigger execution or that normal processing executes the stored pattern.

### JavaScript and TypeScript

JavaScript and TypeScript use the same regex engine and share one pair.

Vulnerable:

```javascript
function searchLogs(userPattern, logLines) {
  const pattern = new RegExp(userPattern);
  return logLines.filter((line) => pattern.test(line));
}
```

Secure:

```javascript
const SAFE_PATTERNS = { error: /^ERROR:/, warning: /^WARNING:/ };

function searchLogs(mode, logLines) {
  const pattern = SAFE_PATTERNS[mode];
  return pattern ? logLines.filter((line) => pattern.test(line)) : [];
}
```

### Go

Go's standard `regexp` package uses a linear time engine, so catastrophic backtracking does not
apply to it.

## Attacker Sized Work

Trace a request size, collection length, or stored configuration into an allocation or loop. Reject
an unsafe value before allocating or iterating. A per item limit is insufficient when an attacker
also controls the item count, so bound cumulative work across the request.

### Python

Vulnerable:

```python
def render_rows(requested_rows: str) -> list[str]:
    return [str(index) for index in range(int(requested_rows))]
```

Secure:

```python
MAX_ROWS = 10_000


def render_rows(requested_rows: str) -> list[str]:
    count = int(requested_rows)
    if count < 0 or count > MAX_ROWS:
        raise ValueError("invalid row count")
    return [str(index) for index in range(count)]
```

### Go

Vulnerable:

```go
package buffers

func allocate(requested int) []byte {
	return make([]byte, requested)
}
```

Secure:

```go
package buffers

const maxBufferSize = 1 << 20

func allocate(requested int) []byte {
	if requested < 0 || requested > maxBufferSize {
		return nil
	}
	return make([]byte, requested)
}
```

## Compressed and Archive Expansion

Enforce limits while reading. Bound actual expanded bytes, archive entry count, and aggregate output.
Do not trust a declared or compressed size as the expanded size.

### Python

Vulnerable compressed stream:

```python
import gzip


def decode_upload(data: bytes) -> bytes:
    return gzip.decompress(data)
```

Secure compressed stream:

```python
import gzip
import io


MAX_OUTPUT_BYTES = 64 * 1024 * 1024


def decode_upload(data: bytes) -> bytes:
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as source:
        output = source.read(MAX_OUTPUT_BYTES + 1)
    if len(output) > MAX_OUTPUT_BYTES:
        raise ValueError("expanded data is too large")
    return output
```

Vulnerable archive:

```python
import io
import zipfile


def read_archive(data: bytes) -> list[bytes]:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        return [archive.read(name) for name in archive.namelist()]
```

Secure archive:

```python
import io
import zipfile


MAX_ENTRIES = 1_000
MAX_OUTPUT_BYTES = 64 * 1024 * 1024


def read_archive(data: bytes) -> list[bytes]:
    files = []
    expanded = 0
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = [entry for entry in archive.infolist() if not entry.is_dir()]
        if len(entries) > MAX_ENTRIES:
            raise ValueError("too many entries")
        for entry in entries:
            remaining = MAX_OUTPUT_BYTES - expanded
            with archive.open(entry) as source:
                content = source.read(remaining + 1)
            if len(content) > remaining:
                raise ValueError("expanded archive is too large")
            expanded += len(content)
            files.append(content)
    return files
```

## Parser Expansion

Use parser enforced limits for nesting and entity expansion, and reject oversized input before
parsing. Report the parser call when attacker controlled input can exceed those limits.

### Python

Vulnerable:

```python
import xml.etree.ElementTree as ET


def parse_xml(data: bytes) -> ET.Element:
    return ET.fromstring(data)
```

Secure:

```python
from lxml import etree


MAX_XML_BYTES = 1_000_000


def parse_xml(data: bytes) -> etree._Element:
    if len(data) > MAX_XML_BYTES:
        raise ValueError("XML input is too large")
    parser = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False)
    return etree.fromstring(data, parser)
```

## Not a Finding

Report only a worker hang, crash, or memory or CPU exhaustion that denies service. A bounded loop,
fixed size allocation, unambiguous regex, capped expanded output, or trusted server configuration is
not a finding. A stored pattern or size is not attacker controlled merely because it exists. Confirm
its writable path and actor. Mere slowness, a missing rate limit, or work bounded by a proven safe
limit is hardening advice.
