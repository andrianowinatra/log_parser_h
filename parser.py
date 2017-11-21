import re
import time
import datetime

import GeoIP

from app import make_app
from app.models import db, LogEntry


def parselogs():
    """This is a management script for the wiki application."""
    # Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken
    current_app = make_app()
    raw_log_pattern_regex = (
        r"^(?P<date>\d{0,4}-\d{2}-\d{2})\s"
        r"(?P<time>\d{2}:\d{2}:\d{2})\s"
        r"(?P<remote_host>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s"
        r"(?P<request_method>\w{3,})\s"
        r"(?P<requested_resource>\/.*?|-)\s"
        r"(?P<query_params>.*?|-)\s"
        r"(?P<remote_port>\d{2,}|-)\s"
        r"(?P<client_username>.*|-)\s"
        r"(?P<client_ip>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s"
        r"(?P<ua_string>.*?|-)\s"
        r"(?P<referrer><.*|\w*.com|http.*|-)\s"
        r"(?P<request_status>\d{1,3})\s"
        r"(?P<request_sub_status>\d{1,})\s"
        r"(?P<windows_status>\d{1,})\s"
        r"(?P<time_taken>\d{1,})$"
    )

    pesky_spaces_regex = r"\s{2,}"
    log_pattern = re.compile(raw_log_pattern_regex, re.DOTALL)
    pesky_spaces = re.compile(pesky_spaces_regex)
    with open("CTF1.log", 'r', errors="replace") as log_file:
        temp_buffer = []
        for line in log_file:
            if line.startswith('#'):
                continue
            elif not re.search(r'\d+$', line):
                temp_buffer.append(line)
            else:
                temp_buffer.append(line)
                complete_line = "".join(temp_buffer)
                processed_line = pesky_spaces.sub(' ', complete_line)
                m = log_pattern.match(processed_line)

                try:
                    end_entry = m.groupdict()
                except:
                    print ("error_parsing: %s" % processed_line)
                    print ("error_raw: %s" % repr(complete_line))
                    time.sleep(5)
                else:
                    temp_buffer = []
                    with current_app.app_context():
                        insert_log_entry(end_entry)

                if 'select' in end_entry["query_params"].lower():
                    print (end_entry)


def insert_log_entry(log_entry):
    # 2015-08-28 18:03:07
    timestamp_format = "%Y-%m-%d %H:%M:%S"
    timestamp_raw = " ".join((log_entry["date"], log_entry["time"]))
    timestamp = datetime.datetime.strptime(timestamp_raw, timestamp_format)
    gi = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)
    client_ip_country = gi.country_name_by_addr("24.24.24.24")
    new_log_entry = LogEntry(
        remote_host=log_entry["remote_host"],
        remote_port=log_entry["remote_port"],
        request_method=log_entry["request_method"],
        requested_resources=log_entry["requested_resource"],
        query_params=log_entry["query_params"],
        client_username=log_entry["client_username"],
        client_ip=log_entry["client_ip"],
        client_ip_country=client_ip_country,
        ua_string=log_entry["ua_string"],
        referrer=log_entry["referrer"],
        request_status=log_entry["request_status"],
        request_sub_status=log_entry["request_sub_status"],
        windows_status=log_entry["windows_status"],
        time_taken=log_entry["time_taken"],
        timestamp=timestamp
    )
    db.session.add(new_log_entry)
    db.session.commit()


if __name__ == '__main__':
    parselogs()
