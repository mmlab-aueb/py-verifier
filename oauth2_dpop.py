"""It includes functions for generating and verifying OAuth 2.0
DPoP based on https://tools.ietf.org/html/draft-fett-oauth-dpop-04
"""
import json
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