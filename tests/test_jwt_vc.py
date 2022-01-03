
import pytest
import requests
import json 
from issuer import Issuer


class TestJWT:

    def test_valid_authorization_get(self):
        token = Issuer().issue_valid_vc()
        headers = {'Authorization':'Bearer ' + token, 'Accept': 'application/json'}
        response  = requests.get("http://localhost:9000/secure/jwt-vc", headers = headers)
        print(response.text)
        assert(response.status_code == 200)

    def test_valid_authorization_post(self):
        token = Issuer().issue_valid_vc()
        headers = {'Authorization':'Bearer ' + token, 'Accept': 'application/json', 'Content-Type': 'application/json'}
        data = {'on': False}
        response  = requests.post("http://localhost:9000/secure/jwt-vc", headers = headers, data = json.dumps(data))
        print(response.text)
        assert(response.status_code == 200)

    def test_valid_authorization_get_with_exp(self):
        token = Issuer().issue_valid_vc_with_exp()
        headers = {'Authorization':'Bearer ' + token, 'Accept': 'application/json'}
        response  = requests.get("http://localhost:9000/secure/jwt-vc", headers = headers)
        print(response.text)
        assert(response.status_code == 200)

    def test_expired(self):
        token = Issuer().issue_expired()
        headers = {'Authorization':'Bearer ' + token, 'Accept': 'application/json'}
        response  = requests.get("http://localhost:9000/secure/jwt-vc", headers = headers)
        print(response.text)
        assert(response.status_code == 401)
