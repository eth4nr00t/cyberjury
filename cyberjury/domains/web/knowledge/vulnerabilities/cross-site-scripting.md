---
id: cross-site-scripting
title: Cross-Site Scripting
lens: cross-site-scripting
impact: HIGH
tags: [cwe-79, owasp-a03, injection]
triggers: ["innerHTML", "dangerouslySetInnerHTML", "|safe", "mark_safe", "render_template_string", "v-html", "document.write", "Markup("]
---

# Cross-Site Scripting

Untrusted data rendered into HTML without context-aware encoding executes as script in the victim's browser. Render data as text, rely on framework auto-escaping, and never disable it for user data.

## JavaScript
Vulnerable:
```javascript
el.innerHTML = "Hello " + username;
```
Secure:
```javascript
el.textContent = "Hello " + username;
```

## Python, Templates
Vulnerable: `return render_template_string("<div>" + user_input + "</div>")`
Secure: rely on Jinja auto-escaping. Never apply `| safe` to user data.
