from flask import jsonify, Blueprint, render_template

from app.models import db, LogEntry

api = Blueprint('control_api', __name__)


@api.route("/")
def index():
    """ return ip list """

    return render_template("index.html")


@api.route("/traffic")
def traffic_list():
    """ return list of unique ips """
    ip_activity_query = db.session.query(LogEntry.client_ip, LogEntry.client_ip_country, db.func.count(LogEntry.client_ip).label("client_count")).\
        group_by(LogEntry.client_ip).\
        yield_per(100)

    json_data = {"unique_clients": [
        {"client_ip": entry.client_ip,
         "client_country": entry.client_ip_country,
         "client_count": entry.client_count} for entry in ip_activity_query]
    }
    return render_template("traffic.html", navigation=json_data["unique_clients"])


@api.route("/traffic/<client_ip>")
def activity_list(client_ip):
    ip_activity_query = db.session.query(LogEntry).\
        filter(LogEntry.client_ip == client_ip).\
        yield_per(100)

    json_data = {"activities": [
        {"host_ip": entry.remote_host,
         "request_method": entry.request_method,
         "requested_resources": entry.requested_resources,
         "query_params": entry.query_params,
         "client_username": entry.client_username,
         "client_ip": entry.client_ip,
         "client_ip_country": entry.client_ip_country,
         "user_agent": entry.ua_string,
         "referrer": entry.referrer,
         "timestamp": entry.timestamp} for entry in ip_activity_query]
    }

    return render_template("ip_traffic.html", navigation=json_data["activities"], header=client_ip)


@api.route("/sqli_exploit")
def sql_injection():
    """ return sql injection checks """

    sql_i_queries = db.session.query(LogEntry).\
        filter(LogEntry.query_params.like('%select %')).\
        yield_per(100)

    json_data = {"activities": [
        {"host_ip": entry.remote_host,
         "request_method": entry.request_method,
         "requested_resources": entry.requested_resources,
         "query_params": entry.query_params,
         "client_username": entry.client_username,
         "client_ip": entry.client_ip,
         "client_ip_country": entry.client_ip_country,
         "user_agent": entry.ua_string,
         "referrer": entry.referrer,
         "timestamp": entry.timestamp} for entry in sql_i_queries]
    }

    return render_template("ip_traffic.html", navigation=json_data["activities"], header="SQL Injections")


@api.route("/lfi_exploit")
def lfi_exploit_list():
    """ return entries that is affected by lfi attack """
    lfi_exploit_queries = db.session.query(LogEntry).\
        filter(LogEntry.query_params.like('%../../%')).\
        yield_per(100)

    json_data = {"activities": [
        {"host_ip": entry.remote_host,
         "request_method": entry.request_method,
         "requested_resources": entry.requested_resources,
         "query_params": entry.query_params,
         "client_username": entry.client_username,
         "client_ip": entry.client_ip,
         "client_ip_country": entry.client_ip_country,
         "user_agent": entry.ua_string,
         "referrer": entry.referrer,
         "timestamp": entry.timestamp} for entry in lfi_exploit_queries]
    }

    return render_template("ip_traffic.html", navigation=json_data["activities"], header="LFI exploit")


@api.route("/rfi_exploit")
def rfi_exploit_list():

    ip_list = db.session.query(LogEntry.client_ip).\
        filter(LogEntry.query_params.like('%../../%')).\
        distinct().\
        yield_per(100)

    json_data = {"activities": []}
    for ip in ip_list:
        activity = db.session.query(LogEntry).\
            filter(LogEntry.client_ip == ip.client_ip).\
            filter(LogEntry.query_params.like('%http%')).\
            filter(LogEntry.query_params.like('%.php')).\
            yield_per(100)
        json_data["activities"].extend([
            {"host_ip": entry.remote_host,
             "request_method": entry.request_method,
             "requested_resources": entry.requested_resources,
             "query_params": entry.query_params,
             "client_username": entry.client_username,
             "client_ip": entry.client_ip,
             "client_ip_country": entry.client_ip_country,
             "user_agent": entry.ua_string,
             "referrer": entry.referrer,
             "timestamp": entry.timestamp} for entry in activity]
        )
    return render_template("ip_traffic.html", navigation=json_data["activities"], header="RFI exploit")
