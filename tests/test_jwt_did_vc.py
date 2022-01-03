
import pytest
import requests
import json 
from issuer import Issuer


class TestJWTwithDIDs:

    def test_valid_didkey_iss(self):
        token = Issuer().issue_valid_did_key_iss()
        headers = {'Authorization':'Bearer ' + token, 'Accept': 'application/json'}
        response  = requests.get("http://localhost:9000/iss-did/jwt-vc", headers = headers)
        print(response.text)
        assert(response.status_code == 200)
