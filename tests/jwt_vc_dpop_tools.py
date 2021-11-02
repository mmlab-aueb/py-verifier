"""It includes functions for generating and verifying OAuth 2.0
DPoP based on https://tools.ietf.org/html/draft-fett-oauth-dpop-04
"""
import json
import random
import time
from jwcrypto import jwt, jwk
from jwcrypto.common import base64url_decode

def verify_dpop (dpop_b64, htu):
    """Verifies a DPoP proof. If the verification succeeds it returns
    True and the DPoP as a jwcrypto.jwt . Otherwise it returns False and None

    :param dpop_b64(string): The base64 encoding of the DPoP HTTP header
    :param htu(string): The value that htu claim of the DPoP should have
    """
    try:
        dpop_b64_header = dpop_b64.split('.')
        dpop_json_header = json.loads(base64url_decode(dpop_b64_header[0]).decode('utf-8'))
        dpop_key = jwk.JWK.from_json(json.dumps(dpop_json_header['jwk'])) 
        dpop_verified = jwt.JWT(jwt=dpop_b64, key=dpop_key)
        return True, dpop_verified
    except:
        return False, None


def generate_dpop(owner_key):
    """
    Generates a DPoP proof

    :param owner_key(jwk.JWK the owner key pair)
    """
    dpop_header = {
        "typ":"dpop+jwt",
        "alg":"EdDSA",
        "jwk": owner_key.export_public(as_dict=True)
    }
    dpop_claims = {
        "jti":"-BwC3ESc6acc2lTc",
        "htm":"POST",
        "htu":"https://server.example.com/token",
        "iat":1562262616
    }
    dpop = jwt.JWT(header = dpop_header, claims = dpop_claims)
    dpop.make_signed_token(owner_key)
    return dpop


def main():
    privatkeyBase64url = "n--gJkymNdp5JQgSfLRoA5T_3nmaLj1THQuOvyrySPs"
    publickeyBase64url = "bKmPLs6MsZaeVtEQF4rCjoVfi37XgRTEl-4ZgqmgBw0"
    jsonkey  = {'kty': 'OKP', 'crv': 'Ed25519', 'x': publickeyBase64url, 'd': privatkeyBase64url}
    owner_key = jwk.JWK.from_json(json.dumps(jsonkey))
    print(owner_key.thumbprint())
    dpop = generate_dpop(owner_key)
    print(dpop.serialize())

if __name__ == '__main__':
    main()