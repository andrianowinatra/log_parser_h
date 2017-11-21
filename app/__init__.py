from flask import Flask
from app.models import db


def make_app():
    app = Flask(__name__)
    app.config.from_pyfile('config.py')

    db.init_app(app)

    from app.blueprints import ip_views

    app.register_blueprint(ip_views.api, url_prefix='/api')
    return app
