import re
import time

# raw_log_pattern_regex = r"^(?P<date>\d{0,4}-\d{2}-\d{2})\s(?P<time>\d{2}:\d{2}:\d{2})\s(?P<remote_host>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s(?P<request_method>\w{3,})\s(?P<requested_resource>\/.*?|-)\s(?P<query_params>.*?|-)\s(?P<https>\d{2,}|-)\s(?P<something>.*?|-)\s(?P<request_ip>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s(?P<ua_string>.*?|-)\s(?P<referrer>.http.*?|\w*.com|-)\s(?P<request_status>\d{1,3})\s(?P<something_1>\d{1,})\s(?P<something_2>\d{1,})\s(?P<something_3>\d{1,})$"
raw_log_pattern_regex = r"^(?P<date>\d{0,4}-\d{2}-\d{2})\s(?P<time>\d{2}:\d{2}:\d{2})\s(?P<remote_host>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s(?P<request_method>\w{3,})\s(?P<requested_resource>\/.*?|-)\s(?P<query_params>.*?|-)\s(?P<https>\d{2,}|-)\s(?P<something>\w*|-)\s(?P<request_ip>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s(?P<ua_string>.*?|-)\s(?P<referrer>http.*|-)\s(?P<request_status>\d{1,3})\s(?P<sub_status>\d{1,})\s(?P<win32_status>\d{1,})\s(?P<time_taken>\d{1,})$"
pesky_spaces_regex = r"\s{2,}"
log_pattern = re.compile(raw_log_pattern_regex, re.DOTALL)

pesky_spaces = re.compile(pesky_spaces_regex)
with open("CTF1.log", 'r', errors="replace", newline='') as log_file:
    for line in log_file:
        if line.startswith('#'):
            continue
        processed_line = pesky_spaces.sub(' ', line)
        m = log_pattern.match(processed_line)

        try:
            print(m.groupdict())
        except:
            print ("error_parsing: %s" % processed_line)
            print ("error_raw: %s" % repr(line))
            time.sleep(5)
