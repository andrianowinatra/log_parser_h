from flask import Flask


def make_app():
    app = Flask(__name__)
    app.config.from_pyfile('config.py')

    @app.route("/api/hello")
    def hello():
        return "Hello World!"

    return app
