from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape
import html

app = FastAPI()

# Set up Jinja2 with autoescape enabled for HTML files
jinja_env = Environment(
    loader=FileSystemLoader("templates"),
    autoescape=select_autoescape(["html", "xml"])  # ✅ Enables escaping
)

@app.get("/", response_class=HTMLResponse)
async def form():
    """
    Render a simple HTML form for submitting the bio.
    """
    return """
    <html>
      <body>
        <h1>Enter your bio</h1>
        <form action="/profile" method="post">
          <textarea name="bio" rows="4" cols="50"></textarea><br>
          <button type="submit">Submit</button>
        </form>
      </body>
    </html>
    """

@app.post("/profile", response_class=HTMLResponse)
async def profile(request: Request, bio: str = Form(...)):
    """
    Render the profile page, escaping any HTML in bio to prevent XSS.
    We explicitly html.escape() the bio, though Jinja2 autoescape already covers it.
    """
    safe_bio = html.escape(bio)
    template = jinja_env.get_template("profile.html")
    rendered = template.render(bio=safe_bio)
    return rendered
