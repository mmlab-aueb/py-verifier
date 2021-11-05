import requests
import json 

token = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOjE2MzYxMDQ4MTUsImV4cCI6MTYzNjE5MTIxNSwiY2FwYWJpbGl0aWVzIjp7IlJhc3BiZXJyeSBQaSI6WyJSRVNUX0FQSSIsIlZJRVdfU1RBVFVTIl19fQ.2YM9587njAmePYqWcHuu5M8mM6HrmYWzteintTGD9SGwOB-B5E-Kb82g-LAVoDRLHGwECgGjDEXle6Oszsy-hw"
headers = {'Authorization':'Bearer ' + token, 'Accept': 'application/json'}
response  = requests.get("http://localhost:9000/secure/jwt-vc", headers = headers)
print(response.text)
