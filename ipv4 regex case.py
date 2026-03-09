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

