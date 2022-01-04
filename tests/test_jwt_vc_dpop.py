import pytest
import requests
import json
from issuer import Issuer
from prover import Prover
from jwcrypto import jwk 


class TestJWTDPoP:
    
    def test_valid_dpop(self):
        key = {'kty': 'EC', 'crv': 'P-256', 'x': 'nVpBMFBRaBxTJ18Xjvu49mAPFdjL1KPwhp7NZcGG06U', 'y': 'qwbPL4x3YXoh6GiuKpYvFZ2QocpimTXjIZIW8UMBh78', 'd': 'Jqjv6ns_eEIG-v1CTfZn5CsvJ1g8Q_j0QXRlZvZA4uY'}
        owner_key = jwk.JWK.from_json(json.dumps(key)) 
        token = Issuer().issue_valid_vc_with_cnf(owner_key)
        dpop = Prover().generate_valid_dpop(owner_key, token)
        headers = {'Authorization':'DPoP ' + token, 'Accept': 'application/json', 'dpop':dpop}
        response  = requests.get("http://localhost:9000/secure/jwt-vc-dpop", headers = headers)
        print(response.text)
        assert(response.status_code == 200)

