---
id: cross-site-scripting
title: Cross-Site Scripting
impact: HIGH
tags: [cwe-79, owasp-a03, injection]
selection_hints: ["innerHTML", "outerHTML", "dangerouslySetInnerHTML", "|safe", "mark_safe", "render_template_string", "v-html", "document.write", "Markup(", "bypassSecurityTrustHtml", "html_safe"]
---

# Cross-Site Scripting

Attacker controlled data rendered into an executable browser context without context aware
encoding can run script in another user's origin. The dangerous operation may be an HTML sink,
a template escape bypass, a script string, an event handler, or an unsafe URL. Report the render
or DOM assignment where untrusted data enters that context, and show how a victim reaches it.
Render plain data as text and preserve framework autoescaping.

## JavaScript

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

## Python, Templates

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

## Go Templates

Vulnerable:

```go
package example

import (
	"html/template"
	"io"
)

func render(w io.Writer, input string) error {
	page := template.Must(template.New("page").Parse(`<div>{{.}}</div>`))
	return page.Execute(w, template.HTML(input))
}
```

Secure:

```go
package example

import (
	"html/template"
	"io"
)

func render(w io.Writer, input string) error {
	page := template.Must(template.New("page").Parse(`<div>{{.}}</div>`))
	return page.Execute(w, input)
}
```

## Not a Finding

Data assigned to `textContent` or emitted through verified autoescaping in the correct output
context is not executable. A sanitizer is safe only for the exact context it produces. HTML body
sanitization does not make a value safe in JavaScript, CSS, an event handler, or a URL. Do not
report a dangerous sink whose value is constant or whose attacker controlled content is encoded
after its final transformation for that exact sink.
