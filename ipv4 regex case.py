from insightlog import analyze_auth_request

test = "invalid user test from 123a456b789c012"
print(analyze_auth_request(test))


import re
from insightlog import IPv4_REGEX

text = "123a456b789c012"
print(re.findall(IPv4_REGEX, text))
print(re.findall(r'\d+.\d+', "123a456"))
print(re.findall(r'\d+\.\d+', "123a456"))
print(re.findall(r'\d+\.\d+', "123.456"))
print(analyze_auth_request("failed login from 999.999.999.999"))

IPv4_REGEX = r'(\d+.\d+.\d+.\d+)' # Simplified regex for IPv4, can be improved to be more strict if needed
# correct regex for IPv4: r'((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)'

AUTH_USER_INVALID_USER = r'(?i)invalid\suser\s(\w+)\s'
AUTH_PASS_INVALID_USER = r'(?i)failed\spassword\sfor\s(\w+)\s'

""" def analyze_auth_request(request_info):
    # Analyze request info and returns main data (IP, invalid user, invalid password's user, is_preauth, is_closed)
    ipv4 = re.findall(IPv4_REGEX, request_info)
    is_preauth = '[preauth]' in request_info.lower()
    invalid_user = re.findall(AUTH_USER_INVALID_USER, request_info)
    invalid_pass_user = re.findall(AUTH_PASS_INVALID_USER, request_info)
    is_closed = 'connection closed by ' in request_info.lower()
    return {'IP': ipv4[0] if ipv4 else None,
            'INVALID_USER': invalid_user[0] if invalid_user else None,
            'INVALID_PASS_USER': invalid_pass_user[0] if invalid_pass_user else None,
            'IS_PREAUTH': is_preauth,
            'IS_CLOSED': is_closed} """

def analyze_auth_request(request_info):
    """Analyze request info and returns main data"""
    
    ipv4_match = re.search(IPv4_REGEX, request_info)
    ipv4 = ipv4_match.group(0) if ipv4_match else None

    is_preauth = '[preauth]' in request_info.lower()

    invalid_user = re.findall(AUTH_USER_INVALID_USER, request_info)
    invalid_pass_user = re.findall(AUTH_PASS_INVALID_USER, request_info)

    is_closed = 'connection closed by ' in request_info.lower()

    return {
        'IP': ipv4,
        'INVALID_USER': invalid_user[0] if invalid_user else None,
        'INVALID_PASS_USER': invalid_pass_user[0] if invalid_pass_user else None,
        'IS_PREAUTH': is_preauth,
        'IS_CLOSED': is_closed
    }

