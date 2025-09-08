from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from jinja2 import Environment, FileSystemLoader

app = FastAPI()

jinja_env = Environment(
    loader=FileSystemLoader("templates"),
    autoescape=False  
)

@app.get("/", response_class=HTMLResponse)
async def form():
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
    template = jinja_env.get_template("profile.html")
    rendered = template.render(bio=bio)
    return rendered
