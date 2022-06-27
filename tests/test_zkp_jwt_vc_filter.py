
import pytest
import requests
from issuer import Issuer


class TestJWT:

    def test_valid_authorization_filter3(self):
        token = Issuer().issue_valid_vc_2()
        headers = {'Authorization':'Bearer ' + token, 'Accept': 'application/json'}
        response  = requests.get("http://localhost:9000/secure/jwt-vc-filter-3?deviceID=device1&field=I1", headers = headers)
        print(response.text)
        assert(response.status_code == 200)
    
