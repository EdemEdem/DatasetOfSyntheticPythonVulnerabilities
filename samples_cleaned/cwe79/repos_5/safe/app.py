import tornado.ioloop
import tornado.web
import os
from tornado.escape import xhtml_escape 

FEEDBACK_STORE = []

class MainHandler(tornado.web.RequestHandler):
    def get(self):
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
        raw = self.get_argument("feedback")
        s = xhtml_escape(raw)
        FEEDBACK_STORE.append(s)
        self.write("<p>Thank you!</p><p><a href='/'>Back</a></p>")

class DashboardHandler(tornado.web.RequestHandler):
    def get(self):
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
    )

if __name__ == "__main__":
    app = make_app()
    app.listen(8888)
    print("Tornado app running on http://localhost:8888")
    tornado.ioloop.IOLoop.current().start()

