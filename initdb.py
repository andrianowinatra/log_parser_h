from app import make_app
from app.models import db


def main():
    curr_app = make_app()
    with curr_app.app_context():
        try:
            db.drop_all()
        except:
            print("db does not exist")
        else:
            print("creating db")
            db.create_all()
        finally:
            print("initdb done")
