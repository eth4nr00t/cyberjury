"""Text extraction for the OpenAI chat-completions response shape.

Shared by OpenAIProvider and LiteLLMProvider, since LiteLLM returns the same
``choices[0].message.content`` structure, a string or a list of content blocks.
"""

from __future__ import annotations

from typing import Any


def choice_text(response: Any) -> str:
    choices = getattr(response, "choices", None) or []
    if not choices:
        return ""
    message = getattr(choices[0], "message", choices[0])
    content = getattr(message, "content", None)
    if content is None and isinstance(message, dict):
        content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, dict) and "text" in block:
                parts.append(str(block["text"]))
            elif isinstance(block, str):
                parts.append(block)
        return "".join(parts)
    return str(content or "")
