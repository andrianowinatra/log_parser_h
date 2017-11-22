import datetime

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class LogEntry(db.Model):
    __tablename__ = 'Log_Entry'
    id_entry = db.Column(db.Integer, primary_key=True)
    remote_host = db.Column(db.Text)
    remote_port = db.Column(db.Text)
    request_method = db.Column(db.Text)
    requested_resources = db.Column(db.Text)
    query_params = db.Column(db.Text)
    client_username = db.Column(db.Text)
    client_ip = db.Column(db.Text)
    client_ip_country = db.Column(db.Text)
    ua_string = db.Column(db.Text)
    referrer = db.Column(db.Text)
    request_status = db.Column(db.Text)
    request_sub_status = db.Column(db.Text)
    windows_status = db.Column(db.Text)
    time_taken = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.now)

