import re
import calendar
import csv
import io
import json
from datetime import datetime

# Service settings
DEFAULT_NGINX = {
    'type': 'web0',
    'dir_path': '/var/log/nginx/',
    'accesslog_filename': 'access.log',
    'errorlog_filename': 'error.log',
    'dateminutes_format': '[%d/%b/%Y:%H:%M',
    'datehours_format': '[%d/%b/%Y:%H',
    'datedays_format': '[%d/%b/%Y',
    'request_model': (r'(\d+\.\d+\.\d+\.\d+)\s-\s-\s'
                      r'\[(.+)\]\s'
                      r'"?(\w+)\s(.+)\s\w+/.+"'
                      r'\s(\d+)\s'
                      r'\d+\s"(.+)"\s'
                      r'"(.+)"'),
    'date_pattern': r'(\d+)/(\w+)/(\d+):(\d+):(\d+):(\d+)',
    'date_keys': {'day': 0, 'month': 1, 'year': 2, 'hour': 3, 'minute': 4, 'second': 5}
}

DEFAULT_APACHE2 = {
    'type': 'web0',
    'dir_path': '/var/log/apache2/',
    'accesslog_filename': 'access.log',
    'errorlog_filename': 'error.log',
    'dateminutes_format': '[%d/%b/%Y:%H:%M',
    'datehours_format': '[%d/%b/%Y:%H',
    'datedays_format': '[%d/%b/%Y',
    'request_model': (r'(\d+\.\d+\.\d+\.\d+)\s-\s-\s'
                      r'\[(.+)\]\s'
                      r'"?(\w+)\s(.+)\s\w+/.+"'
                      r'\s(\d+)\s'
                      r'\d+\s"(.+)"\s'
                      r'"(.+)"'),
    'date_pattern': r'(\d+)/(\w+)/(\d+):(\d+):(\d+):(\d+)',
    'date_keys': {'day': 0, 'month': 1, 'year': 2, 'hour': 3, 'minute': 4, 'second': 5}
}

DEFAULT_AUTH = {
    'type': 'auth',
    'dir_path': '/var/log/',
    'accesslog_filename': 'auth.log',
    'dateminutes_format': '%b %e %H:%M:',
    'datehours_format': '%b %e %H:',
    'datedays_format': '%b %e ',
    'request_model': (r'(\w+\s\s\d+\s\d+:\d+:\d+)\s'
                      r'\w+\s(\w+)\[\d+\]:\s'
                      r'(.+)'),
    'date_pattern': r'(\w+)\s(\s\d+|\d+)\s(\d+):(\d+):(\d+)',
    'date_keys': {'month': 0, 'day': 1, 'hour': 2, 'minute': 3, 'second': 4}
}

SERVICES_SWITCHER = {
    'nginx': DEFAULT_NGINX,
    'apache2': DEFAULT_APACHE2,
    'auth': DEFAULT_AUTH
}

IPv4_REGEX = r'(\d+.\d+.\d+.\d+)'
AUTH_USER_INVALID_USER = r'(?i)invalid\suser\s(\w+)\s'
AUTH_PASS_INVALID_USER = r'(?i)failed\spassword\sfor\s(\w+)\s'
LOG_LEVEL_INFO = 'info'
LOG_LEVEL_WARNING = 'warning'
LOG_LEVEL_ERROR = 'error'
LOG_LEVEL_CHOICES = [LOG_LEVEL_INFO, LOG_LEVEL_WARNING, LOG_LEVEL_ERROR]
TIME_RANGE_FORMAT = '%Y-%m-%d %H:%M:%S'
OUTPUT_FORMAT_TEXT = 'text'
OUTPUT_FORMAT_JSON = 'json'
OUTPUT_FORMAT_CSV = 'csv'
OUTPUT_FORMAT_CHOICES = [OUTPUT_FORMAT_TEXT, OUTPUT_FORMAT_JSON, OUTPUT_FORMAT_CSV]


# Validator functions
def is_valid_year(year):
    """Check if year's value is valid"""
    return 2030 >= year > 1970


def is_valid_month(month):
    """Check if month's value is valid"""
    return 12 >= month > 0


def is_valid_day(day):
    """Check if day value is valid"""
    return 31 >= day > 0


def is_valid_hour(hour):
    """Check if hour value is valid"""
    return (hour == '*') or (23 >= hour >= 0)


def is_valid_minute(minute):
    """Check if minute value is valid"""
    return (minute == '*') or (59 >= minute >= 0)


# Utility functions
def get_service_settings(service_name):
    """Get default settings for the said service"""
    if service_name in SERVICES_SWITCHER:
        return SERVICES_SWITCHER.get(service_name)
    else:
        raise Exception("Service \""+service_name+"\" doesn't exists!")


def get_date_filter(settings, minute=datetime.now().minute, hour=datetime.now().hour,
                    day=datetime.now().day, month=datetime.now().month,
                    year=datetime.now().year):
    """Get the date pattern that can be used to filter data from logs based on the params"""
    if not is_valid_year(year) or not is_valid_month(month) or not is_valid_day(day) \
            or not is_valid_hour(hour) or not is_valid_minute(minute):
        raise Exception("Date elements aren't valid")
    if minute != '*' and hour != '*':
        date_format = settings['dateminutes_format']
        date_filter = datetime(year, month, day, hour, minute).strftime(date_format)
    elif minute == '*' and hour != '*':
        date_format = settings['datehours_format']
        date_filter = datetime(year, month, day, hour).strftime(date_format)
    elif minute == '*' and hour == '*':
        date_format = settings['datedays_format']
        date_filter = datetime(year, month, day).strftime(date_format)
    else:
        raise Exception("Date elements aren't valid")
    return date_filter


def check_match(line, filter_pattern, is_regex=False, is_casesensitive=True, is_reverse=False):
    """Check if line contains/matches filter pattern"""
    if is_regex:
        check_result = re.search(filter_pattern, line) if is_casesensitive \
            else re.search(filter_pattern, line, re.IGNORECASE)
    else:
        check_result = (filter_pattern in line) if is_casesensitive else (filter_pattern.lower() in line.lower())
    if is_reverse:
        return not check_result
    return check_result


def filter_data(log_filter, data=None, filepath=None, is_casesensitive=True, is_regex=False, is_reverse=False):
    """Filter received data/file content and return the results"""
    return_data = ""
    if filepath:
        try:
            with open(filepath, 'r') as file_object:
                for line in file_object:
                    if check_match(line, log_filter, is_regex, is_casesensitive, is_reverse):
                        return_data += line
            return return_data
        except (IOError, EnvironmentError) as e:
            print(e.strerror)
            return None
    elif data:
        for line in data.splitlines():
            if check_match(line, log_filter, is_regex, is_casesensitive, is_reverse):
                return_data += line+"\n"
        return return_data
    else:
        raise Exception("Data and filepath values are NULL!")


def _get_iso_datetime(str_date, pattern, keys):
    """Change raw datetime from logs to ISO 8601 format."""
    months_dict = {v: k for k, v in enumerate(calendar.month_abbr)}
    matches = re.findall(pattern, str_date)
    if not matches:
        raise ValueError(f"Date pattern '{pattern}' did not match '{str_date}'")
    a_date = matches[0]
    d_datetime = datetime(int(a_date[keys['year']]) if 'year' in keys else _get_auth_year(),
                          months_dict[a_date[keys['month']]], int(a_date[keys['day']].strip()),
                          int(a_date[keys['hour']]), int(a_date[keys['minute']]), int(a_date[keys['second']]))
    return d_datetime.isoformat(' ')


def _get_auth_year():
    """Return the year when the requests happened"""
    if datetime.now().month == 1 and datetime.now().day == 1 and datetime.now().hour == 0:
        return datetime.now().year - 1
    else:
        return datetime.now().year


def get_web_requests(data, pattern, date_pattern=None, date_keys=None):
    """Analyze data (from the logs) and return list of requests formatted as the model (pattern) defined."""
    if date_pattern and not date_keys:
        raise Exception("date_keys is not defined")
    requests_dict = re.findall(pattern, data, flags=re.IGNORECASE)
    requests = []
    for request_tuple in requests_dict:
        if date_pattern:
            str_datetime = _get_iso_datetime(request_tuple[1], date_pattern, date_keys)
        else:
            str_datetime = request_tuple[1]
        requests.append({'DATETIME': str_datetime, 'IP': request_tuple[0],
                         'METHOD': request_tuple[2], 'ROUTE': request_tuple[3], 'CODE': request_tuple[4],
                         'REFERRER': request_tuple[5], 'USERAGENT': request_tuple[6]})
    return requests


def get_auth_requests(data, pattern, date_pattern=None, date_keys=None):
    """Analyze data (from the logs) and return list of auth requests formatted as the model (pattern) defined."""
    requests_dict = re.findall(pattern, data)
    requests = []
    for request_tuple in requests_dict:
        if date_pattern:
            str_datetime = _get_iso_datetime(request_tuple[0], date_pattern, date_keys)
        else:
            str_datetime = request_tuple[0]
        data = analyze_auth_request(request_tuple[2])
        data['DATETIME'] = str_datetime
        data['SERVICE'] = request_tuple[1]
        requests.append(data)
    return requests


def analyze_auth_request(request_info):
    """Analyze request info and returns main data (IP, invalid user, invalid password's user, is_preauth, is_closed)"""
    ipv4 = re.findall(IPv4_REGEX, request_info)
    is_preauth = '[preauth]' in request_info.lower()
    invalid_user = re.findall(AUTH_USER_INVALID_USER, request_info)
    invalid_pass_user = re.findall(AUTH_PASS_INVALID_USER, request_info)
    is_closed = 'connection closed by ' in request_info.lower()
    return {'IP': ipv4[0] if ipv4 else None,
            'INVALID_USER': invalid_user[0] if invalid_user else None,
            'INVALID_PASS_USER': invalid_pass_user[0] if invalid_pass_user else None,
            'IS_PREAUTH': is_preauth,
            'IS_CLOSED': is_closed}


def get_log_level(service, request):
    """Infer a normalized log level from a parsed request."""
    if service in ('nginx', 'apache2'):
        try:
            code = int(request.get('CODE', 0))
        except (TypeError, ValueError):
            return LOG_LEVEL_INFO
        if 500 <= code:
            return LOG_LEVEL_ERROR
        if 400 <= code:
            return LOG_LEVEL_WARNING
        return LOG_LEVEL_INFO

    if service == 'auth':
        if request.get('INVALID_USER') or request.get('INVALID_PASS_USER') or request.get('IS_CLOSED'):
            return LOG_LEVEL_ERROR
        if request.get('IS_PREAUTH'):
            return LOG_LEVEL_WARNING
        return LOG_LEVEL_INFO

    return LOG_LEVEL_INFO


def filter_requests_by_level(requests, service, log_level):
    """Filter parsed requests by inferred log level."""
    if not log_level:
        return requests
    return [request for request in requests if get_log_level(service, request) == log_level]


def parse_datetime_value(value):
    """Parse datetime string used by parsed requests and CLI time-range arguments."""
    return datetime.strptime(value, TIME_RANGE_FORMAT)


def filter_requests_by_time_range(requests, time_from=None, time_to=None):
    """Filter parsed requests by DATETIME range (inclusive)."""
    if not time_from and not time_to:
        return requests
    if time_from and time_to and time_from > time_to:
        raise ValueError("time_from must be less than or equal to time_to")

    filtered_requests = []
    for request in requests:
        request_datetime = request.get('DATETIME')
        if not request_datetime:
            continue
        try:
            parsed_datetime = parse_datetime_value(request_datetime)
        except ValueError:
            continue
        if time_from and parsed_datetime < time_from:
            continue
        if time_to and parsed_datetime > time_to:
            continue
        filtered_requests.append(request)
    return filtered_requests


def format_requests_as_json(requests):
    """Format parsed requests as JSON text."""
    return json.dumps(requests, indent=2, ensure_ascii=False)


def format_requests_as_csv(requests):
    """Format parsed requests as CSV text."""
    if not requests:
        return ''

    fieldnames = list(requests[0].keys())
    for request in requests[1:]:
        for key in request.keys():
            if key not in fieldnames:
                fieldnames.append(key)

    out_buffer = io.StringIO()
    writer = csv.DictWriter(out_buffer, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(requests)
    return out_buffer.getvalue()


# Simplified analyzer functions (replacing the class)
def apply_filters(filters, data=None, filepath=None):
    """Apply all filters to data or file and return filtered results"""
    if filepath:
        try:
            with open(filepath, 'r') as file_object:
                filtered_lines = []
                for line in file_object:
                    if check_all_matches(line, filters):
                        filtered_lines.append(line)
                return ''.join(filtered_lines)
        except (IOError, EnvironmentError) as e:
            print(e.strerror)
            return None
    elif data:
        filtered_lines = []
        for line in data.splitlines():
            if check_all_matches(line, filters):
                filtered_lines.append(line + "\n")
        return ''.join(filtered_lines)
    else:
        raise Exception("Either data or filepath must be provided")


def check_all_matches(line, filter_patterns):
    """Check if line contains/matches all filter patterns"""
    if not filter_patterns:
        return True
    result = True
    for pattern_data in filter_patterns:
        tmp_result = check_match(line=line, **pattern_data)
        result = result and tmp_result
    return result


def get_requests(service, data=None, filepath=None, filters=None):
    """Analyze data and return list of requests. Main function to get parsed requests."""
    settings = get_service_settings(service)
    
    # Determine filepath if not provided
    if not filepath and not data:
        filepath = settings['dir_path'] + settings['accesslog_filename']
    
    # Apply filters if provided
    if filters:
        filtered_data = apply_filters(filters, data=data, filepath=filepath)
    else:
        if filepath:
            try:
                with open(filepath, 'r') as f:
                    filtered_data = f.read()
            except (IOError, EnvironmentError) as e:
                print(e.strerror)
                return None
        else:
            filtered_data = data
    
    if not filtered_data:
        return []
    
    # Parse requests based on service type
    request_pattern = settings['request_model']
    date_pattern = settings['date_pattern']
    date_keys = settings['date_keys']
    
    if settings['type'] == 'web0':
        return get_web_requests(filtered_data, request_pattern, date_pattern, date_keys)
    elif settings['type'] == 'auth':
        return get_auth_requests(filtered_data, request_pattern, date_pattern, date_keys)
    else:
        return None


# CLI entry point
if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description="Analyze server log files (nginx, apache2, auth)")
    parser.add_argument('--service', required=True, choices=['nginx', 'apache2', 'auth'], help='Type of log to analyze')
    parser.add_argument('--logfile', required=True, help='Path to the log file')
    parser.add_argument('--filter', required=False, default=None, help='String to filter log lines')
    parser.add_argument('--log-level', required=False, choices=LOG_LEVEL_CHOICES,
                        help='Filter parsed requests by inferred log level')
    parser.add_argument('--time-from', required=False, default=None,
                        help='Start datetime (inclusive), format: YYYY-MM-DD HH:MM:SS')
    parser.add_argument('--time-to', required=False, default=None,
                        help='End datetime (inclusive), format: YYYY-MM-DD HH:MM:SS')
    parser.add_argument('--output-format', required=False, default=OUTPUT_FORMAT_TEXT, choices=OUTPUT_FORMAT_CHOICES,
                        help='Output format: text, json, or csv')
    args = parser.parse_args()

    try:
        time_from = parse_datetime_value(args.time_from) if args.time_from else None
        time_to = parse_datetime_value(args.time_to) if args.time_to else None
    except ValueError:
        parser.error("Invalid datetime format for --time-from/--time-to. Use YYYY-MM-DD HH:MM:SS")

    if time_from and time_to and time_from > time_to:
        parser.error("--time-from must be less than or equal to --time-to")

    filters = []
    if args.filter:
        filters.append({'filter_pattern': args.filter, 'is_casesensitive': True, 'is_regex': False, 'is_reverse': False})
    
    requests = get_requests(args.service, filepath=args.logfile, filters=filters)
    if requests is not None:
        requests = filter_requests_by_level(requests, args.service, args.log_level)
        requests = filter_requests_by_time_range(requests, time_from, time_to)
        if args.output_format == OUTPUT_FORMAT_JSON:
            print(format_requests_as_json(requests))
        elif args.output_format == OUTPUT_FORMAT_CSV:
            print(format_requests_as_csv(requests), end='')
        else:
            for req in requests:
                print(req)

