
import pytest
import requests
import json 
from issuer import Issuer


class TestJWT:

    def test_revoked(self):
        token = Issuer().issue_revoked_vc()
        headers = {'Authorization':'Bearer ' + token, 'Accept': 'application/json'}
        response  = requests.get("http://localhost:9000/secure/jwt-vc-with-revocation", headers = headers)
        print(response.text)
        assert(response.status_code == 401)
    
    def test_non_revoked(self):
        token = Issuer().issue_non_revoked_vc()
        headers = {'Authorization':'Bearer ' + token, 'Accept': 'application/json'}
        response  = requests.get("http://localhost:9000/secure/jwt-vc-with-revocation", headers = headers)
        print(response.text)
        assert(response.status_code == 200)
