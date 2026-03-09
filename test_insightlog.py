from insightlog import get_requests

result = get_requests("nginx", filepath="fake_file.log")
print(result)


for r in get_requests("nginx", filepath="fake_file.log"):
    print(r)
    
