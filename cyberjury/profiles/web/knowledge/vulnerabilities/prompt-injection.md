---
id: prompt-injection
title: Prompt Injection
impact: HIGH
tags: [cwe-1427, owasp-llm01]
selection_hints: ["system prompt", "system_prompt", "messages.append", "chat.completions", "responses.create", "TextContent", "CallToolResult", "tool_result", "@mcp.tool", "call_tool", "prompt template", "prompt_template", "f\"You are", "untrusted content"]
---

# Prompt Injection

## Security Condition

Untrusted content can contain instructions that steer a language model. The flow becomes an
exploitable security issue when model output can trigger a privileged tool or action without a
deterministic control that independently authorizes the exact effect. An attacker can then use a
request, fetched page, tool result, or stored record to send data, delete records, transfer value,
or cross another trust boundary.

## Review Guidance

Report the dispatch from model output to the capable action and show the attacker controlled
content, missing control, and unauthorized effect. Separating content from instructions can reduce
confusion, but it is not an authorization boundary.

### Trace the Capable Action

Trace the content to its attacker controlled source and the model output to a capable action. The
reportable location is the dispatch that treats the model decision as authority, or the tool
boundary that accepts it without an independent policy check. A specific jailbreak string is not
required when the code exposes this control flow, but untrusted text reaching a model is only a
candidate until a concrete unauthorized effect is reachable.

## Examples

### Untrusted Content with Tool Access

Vulnerable:

```python
def process_page(page: str, model, tools):
    messages = [{"role": "user", "content": f"Summarize and act on:\n{page}"}]
    requested_action = model(messages)
    return tools[requested_action]()
```

Secure:

```python
def summarize_page(page: str, model) -> str:
    messages = [
        {
            "role": "user",
            "content": [
                {"type": "text", "text": "Summarize the untrusted document."},
                {"type": "text", "text": page},
            ],
        }
    ]
    return model(messages)
```

Separating data reduces instruction confusion but is not an authorization boundary. The strong
control is downstream. A tool that sends, deletes, pays, or grants must require a check the
injected text cannot satisfy, such as operator confirmation or an allowlist bound to the
authenticated caller.

### Authority for Model Selected Actions

Vulnerable:

```python
def process_document(store, model, document_id):
    document = store.fetch(document_id)
    if model(document.body) == "delete":
        store.delete(document_id)
```

Secure:

```python
def process_document(context, model, document_id):
    document = context.document_store.fetch(document_id)
    if model(document.body) != "delete":
        return
    if "document:delete" not in context.principal.permissions:
        raise PermissionError("delete permission required")
    if document_id not in context.confirmed_document_deletes:
        raise PermissionError("document delete confirmation required")
    context.document_store.delete(document_id)
```

A tool result, resource body, stored document, or tool description built from untrusted data can
carry an injected instruction to the model. The transport format does not make that content
trusted. The secure flow derives authority and an exact operator confirmed action from an
authenticated context, not from an argument or decision the model supplies.

## Not a Finding

Content that traces only to trusted data, constant strings, or operator supplied configuration is
not prompt injection. Untrusted content sent to a model is not reportable when no capable action is
reachable, or when every effect requires an independent authorization and exact confirmation that
the model cannot forge. Prompt hardening text alone is not a security boundary. A model that only
produces text for a person to evaluate, with no automated capability, is out of scope.
