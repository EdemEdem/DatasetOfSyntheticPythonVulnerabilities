import tornado.ioloop
import tornado.web
import os

# In-memory store for simplicity
FEEDBACK_STORE = []

class MainHandler(tornado.web.RequestHandler):
    def get(self):
        # Render form to submit feedback
        self.write("""
            <h1>Submit Feedback</h1>
            <form action="/submit" method="post">
                <textarea name="feedback" rows="4" cols="40"></textarea><br>
                <button type="submit">Send</button>
            </form>
            <p><a href="/dashboard">View Dashboard</a></p>
        """)

class SubmitHandler(tornado.web.RequestHandler):
    def post(self):
        # Source: directly get user input
        feedback = self.get_argument("feedback")
        # Store it (no sanitization)
        FEEDBACK_STORE.append(feedback)
        self.write("<p>Thank you!</p><p><a href='/'>Back</a></p>")

class DashboardHandler(tornado.web.RequestHandler):
    def get(self):
        # Render all feedback entries via template
        self.render("dashboard.html", feedback_list=FEEDBACK_STORE)

def make_app():
    return tornado.web.Application(
        [
            (r"/", MainHandler),
            (r"/submit", SubmitHandler),
            (r"/dashboard", DashboardHandler),
        ],
        template_path=os.path.join(os.path.dirname(__file__), "templates"),
        debug=True,
        autoescape=None
    )

if __name__ == "__main__":
    app = make_app()
    app.listen(8888)
    print("Vulnerable Tornado app running on http://localhost:8888")
    tornado.ioloop.IOLoop.current().start()
