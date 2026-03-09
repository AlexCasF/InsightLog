"""
Standalone module to debug IPv4 extraction bug from insightlog.py
"""

import re


# =========================================================
# IPv4 REGEX (from insightlog.py)
# =========================================================

IPv4_REGEX = r'\b((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b'


# =========================================================
# AUTH LOG PATTERNS (from insightlog.py)
# =========================================================

AUTH_USER_INVALID_USER = r'(?i)invalid\suser\s(\w+)\s'
AUTH_PASS_INVALID_USER = r'(?i)failed\spassword\sfor\s(\w+)\s'


# =========================================================
# ORIGINAL BUGGY FUNCTION (as in insightlog.py)
# =========================================================

def analyze_auth_request_buggy(request_info):
    """
    Original function from insightlog.py that contains the IPv4 bug
    """

    # BUG: findall with grouped regex returns tuples
    ipv4 = re.findall(IPv4_REGEX, request_info)

    is_preauth = '[preauth]' in request_info.lower()
    invalid_user = re.findall(AUTH_USER_INVALID_USER, request_info)
    invalid_pass_user = re.findall(AUTH_PASS_INVALID_USER, request_info)
    is_closed = 'connection closed by ' in request_info.lower()

    return {
        'IP': ipv4[0] if ipv4 else None,
        'INVALID_USER': invalid_user[0] if invalid_user else None,
        'INVALID_PASS_USER': invalid_pass_user[0] if invalid_pass_user else None,
        'IS_PREAUTH': is_preauth,
        'IS_CLOSED': is_closed
    }


# =========================================================
# CORRECTED FUNCTION
# =========================================================

def analyze_auth_request_fixed(request_info):
    """
    Fixed version using re.search instead of re.findall
    """

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


# =========================================================
# TEST CASES
# =========================================================

def run_tests():
    """
    Demonstrates the difference between buggy and fixed versions
    """

    test_cases = [
        "Failed password for root from 192.168.1.10 port 22 ssh2",
        "invalid user admin from 10.0.0.5 port 22",
        "invalid user test from 123a456b789c012"
    ]

    for test in test_cases:

        print("\n==============================")
        print("Log line:")
        print(test)

        print("\nBuggy Result:")
        print(analyze_auth_request_buggy(test))

        print("\nFixed Result:")
        print(analyze_auth_request_fixed(test))


# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":
    run_tests()