from flask import Flask
from app.models import db


def make_app():
    app = Flask(__name__)
    app.config.from_pyfile('config.py')

    db.init_app(app)

    @app.route("/api/hello")
    def hello():
        return "Hello World!"

    return app
