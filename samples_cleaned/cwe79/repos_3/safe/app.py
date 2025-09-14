import html
from bottle import Bottle, request, run, HTTPResponse

app = Bottle()

@app.post("/render")
def render_content_safe():
    data = request.json or {}
    content = data.get("content", "")
    s_content = html.escape(content)
    html_body = "<div>" + s_content + "</div>"
    return HTTPResponse(status=200, body=html_body, headers={"Content-Type": "text/html"})

if __name__ == "__main__":
    run(app, host="0.0.0.0", port=8080, debug=True)
