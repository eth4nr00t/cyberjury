---
id: cross-site-scripting
title: Cross-Site Scripting
impact: HIGH
tags: [cwe-79, owasp-a03, injection]
selection_hints: ["innerHTML", "outerHTML", "dangerouslySetInnerHTML", "|safe", "mark_safe", "render_template_string", "v-html", "document.write", "Markup(", "bypassSecurityTrustHtml", "html_safe"]
---

# Cross-Site Scripting

Attacker controlled data rendered into an executable browser context without the control for that
context can run script in another user's origin. Report the final render or DOM assignment and show
how a victim reaches it. HTML body data, template escape bypasses, executable JavaScript contexts,
and browser URL sinks require different controls.

## HTML Body Sinks

Vulnerable:

```javascript
function greet(element, username) {
  element.innerHTML = "Hello " + username
}
```

Secure:

```javascript
function greet(element, username) {
  element.textContent = "Hello " + username
}
```

## Template Escape Bypasses

Vulnerable:

```python
def render_message(render_template_string, user_input):
    return render_template_string("<div>" + user_input + "</div>")
```

Secure:

```python
def render_message(render_template, user_input):
    return render_template("message.html", message=user_input)
```

The secure template contains `{{ message }}` in an autoescaped HTML context.

## Executable Event Contexts

Vulnerable:

```javascript
function bindAction(element, action) {
  element.setAttribute("onclick", action)
}
```

Secure:

```javascript
const HANDLERS = {
  hide: element => { element.hidden = true },
}

function bindAction(element, action) {
  const handler = HANDLERS[action]
  if (!handler) throw new Error("unknown action")
  element.addEventListener("click", () => handler(element))
}
```

The secure mapping contains only fixed functions chosen by trusted code. Escaping a string and
placing it inside an event handler is not an equivalent control.

## Browser URL Sinks

Vulnerable:

```javascript
function setProfileLink(link, target) {
  link.href = target
}
```

Secure:

```javascript
function setProfileLink(link, target) {
  const parsed = new URL(target, "https://app.example.com")
  if (parsed.origin !== "https://app.example.com") throw new Error("untrusted origin")
  link.href = parsed.href
}
```

## Not a Finding

Data assigned to `textContent` or emitted through verified autoescaping in the correct output
context is not executable. A closed event map avoids compiling attacker text. A URL selected from
an exact trusted origin or route allowlist cannot use an executable scheme. A sanitizer is safe
only for the exact context it produces. HTML body sanitization does not make a value safe in
JavaScript, CSS, an event handler, or a URL. Do not report a dangerous sink whose value is constant
or whose attacker controlled content is controlled after its final transformation for that sink.
