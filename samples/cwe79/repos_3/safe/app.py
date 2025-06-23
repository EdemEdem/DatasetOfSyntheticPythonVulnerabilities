import html
from bottle import Bottle, request, run, HTTPResponse

app = Bottle()

@app.post("/render")
def render_content_safe():
    """
    Safe endpoint: takes JSON { "content": ... }, escapes it via html.escape,
    then inlines into HTML. This prevents XSS (CWE-79).
    """
    data = request.json or {}
    # SOURCE: untrusted JSON field
    content = data.get("content", "")
    # SANITIZER: escape all HTML-special characters
    safe_content = html.escape(content)
    # SINK: safe concatenation into HTML
    html_body = "<div>" + safe_content + "</div>"
    return HTTPResponse(status=200, body=html_body, headers={"Content-Type": "text/html"})

if __name__ == "__main__":
    # Run on localhost:8080 for testing
    run(app, host="0.0.0.0", port=8080, debug=True)
