
import pytest
import requests
import json 
from issuer import Issuer
from prover import Prover
from jwcrypto import jwt, jwk
from jwcrypto.common import base64url_decode, base64url_encode
import base58


class TestJWTwithDIDs:

    def test_valid_didkey_iss(self):
        token = Issuer().issue_valid_did_key_iss()
        headers = {'Authorization':'Bearer ' + token, 'Accept': 'application/json'}
        response  = requests.get("http://localhost:9000/iss-did/jwt-vc", headers = headers)
        print(response.text)
        assert(response.status_code == 200)

    def test_valid_dpop_with_did(self):
        '''
        For this we need Ed25519 keys
        >>> key = jwk.JWK.generate(kty='OKP', crv='Ed25519')
        >>> print (key.export(as_dict=True))
        '''
        key = {'kty': 'OKP', 'crv': 'Ed25519', 'x': 'vnTP8BkkMuw99RsdN0Vw0f--hUqKWsU9rTnb8mV03hg', 'd': 'brF6hpvy4t6Puc_JC01B_W4V9rj1pwa8IHbgMUTWrMY'}
        owner_key = jwk.JWK.from_json(json.dumps(key))
        owner_did = "did:key:z" + base58.b58encode( b'\xed\x01'+base64url_decode(owner_key['x'])).decode()
        token = Issuer().issue_valid_vc_with_sub(owner_did)
        dpop = Prover().generate_valid_dpop(owner_key, token, alg="EdDSA")
        headers = {'Authorization':'DPoP ' + token, 'Accept': 'application/json', 'dpop':dpop}
        response  = requests.get("http://localhost:9000/secure/jwt-vc-dpop", headers = headers)
        print(response.text)
        assert(response.status_code == 200)
