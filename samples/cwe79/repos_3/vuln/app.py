from bottle import Bottle, request, run, HTTPResponse

app = Bottle()

@app.post("/render")
def render_content():
    """
    Vulnerable endpoint: takes JSON { "content": ... } and inlines it
    without escaping. This is subject to stored/reflected XSS (CWE-79).
    """
    data = request.json or {}
    # SOURCE: untrusted JSON field
    content = data.get("content", "")
    # SINK: direct concatenation into HTML
    html_body = "<div>" + content + "</div>"
    return HTTPResponse(status=200, body=html_body, headers={"Content-Type": "text/html"})

if __name__ == "__main__":
    # Run on localhost:8080 for testing
    run(app, host="0.0.0.0", port=8080, debug=True)
