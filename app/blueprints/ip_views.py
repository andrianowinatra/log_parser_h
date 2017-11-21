from flask import jsonify, Blueprint

from app.models import db, LogEntry

api = Blueprint('control_api', __name__)


@api.route("/ip_list")
def ip_list():
    """ return ip list """

    ip_query = db.session.query(LogEntry.remote_host).\
        group_by(LogEntry.remote_host).\
        all()

    json_data = {"unique_ips": [ip_address.remote_host for ip_address in ip_query]}
    return jsonify(json_data)


@api.route("/traffic/<host_ip>")
def traffic_list(host_ip):
    """ return list of unique ips """
    ip_activity_query = db.session.query(LogEntry.client_ip, LogEntry.client_ip_country, db.func.count(LogEntry.client_ip).label("client_count")).\
        filter(LogEntry.remote_host == host_ip).\
        group_by(LogEntry.client_ip).\
        all()

    json_data = {"unique_clients": [
        {"client_ip": entry.client_ip,
         "client_country": entry.client_ip_country,
         "client_count": entry.client_count} for entry in ip_activity_query]
    }

    return jsonify(json_data)


@api.route("/traffic/<host_ip>/<client_ip>")
def activity_list(host_ip, client_ip):
    ip_activity_query = db.session.query(LogEntry).\
        filter(LogEntry.remote_host == host_ip).\
        filter(LogEntry.client_ip == client_ip).\
        all()

    json_data = {"activities": [
        {"request_method": entry.request_method,
         "requested_resources": entry.requested_resources,
         "query_params": entry.query_params,
         "client_username": entry.client_username,
         "client_ip": entry.client_ip,
         "client_ip_country": entry.client_ip_country,
         "user_agent": entry.ua_string,
         "referrer": entry.referrer,
         "timestamp": entry.timestamp} for entry in ip_activity_query]
    }

    return jsonify(json_data)
