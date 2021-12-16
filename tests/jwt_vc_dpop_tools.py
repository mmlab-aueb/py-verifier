"""It includes functions for generating and verifying OAuth 2.0
DPoP based on https://tools.ietf.org/html/draft-fett-oauth-dpop-04
"""
import json
import random
import time
import hashlib
from jwcrypto import jwt, jwk
from jwcrypto.common import base64url_decode, base64url_encode



def verify_dpop(dpop_b64, htu):
    """Verifies a DPoP proof. If the verification succeeds it returns
    True and the DPoP as a jwcrypto.jwt . Otherwise it returns False and None

    :param dpop_b64(string): The base64 encoding of the DPoP HTTP header
    :param htu(string): The value that htu claim of the DPoP should have
    """
    try:
        dpop_b64_header = dpop_b64.split('.')
        dpop_json_header = json.loads(
            base64url_decode(dpop_b64_header[0]).decode('utf-8'))
        dpop_key = jwk.JWK.from_json(json.dumps(dpop_json_header['jwk']))
        dpop_verified = jwt.JWT(jwt=dpop_b64, key=dpop_key)
        return True, dpop_verified
    except:
        return False, None


def generate_dpop(owner_key, access_token):
    """
    Generates a DPoP proof

    :param owner_key(jwk.JWK the owner key pair)
    """
    dpop_header = {
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": owner_key.export_public(as_dict=True)
    }
    dpop_claims = {
        "jti": "-BwC3ESc6acc2lTc",
        "htm": "GET",
        "htu": "https://remote.cloud/zerocorp",
        "iat": 1562262616,
        "ath": base64url_encode(hashlib.sha256(access_token.encode('utf-8')).digest())
    }
    dpop = jwt.JWT(header=dpop_header, claims=dpop_claims)
    dpop.make_signed_token(owner_key)
    return dpop


def main():
    '''
    >>> key = jwk.JWK.generate(kty='EC', crv='P-256')
    >>> print (key.export(as_dict=True))
    '''
    OWNER_KEY = {'kty': 'EC', 'crv': 'P-256', 'x': 'z30WuxpsPow8KpH0N93vW24nA0HD48_MluqgdEUvtU4', 'y': 'VcKco12BZFPu5HU2LBLotTD9NitdlNxnBLngD-eTapM', 'd': 'UCe_iiyGTQf13KyLPhLgjVCT3gSx4APgNSbS7uyLxN8'}

    VC = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5tbWxhYi5lZHUuZ3IiLCJjbmYiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJ6MzBXdXhwc1BvdzhLcEgwTjkzdlcyNG5BMEhENDhfTWx1cWdkRVV2dFU0IiwieSI6IlZjS2NvMTJCWkZQdTVIVTJMQkxvdFREOU5pdGRsTnhuQkxuZ0QtZVRhcE0ifSwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL21tLmF1ZWIuZ3IvY29udGV4dHMvY2FwYWJpbGl0aWVzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJDYXBhYmlsaXRpZXNDcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImNhcGFiaWxpdGllcyI6eyJDbG91ZCBzdG9yYWdlIjpbIkZMX1JFQUQiXX19fX0.ibjct11ZXik3He2n-GfugMyTT5qHOJpm7qqvZHJIzEq1SDnnL1_pbAwtfNg3nHnzw7eliHtotHj3SlDzBStMVQ"

    owner_key = jwk.JWK.from_json(json.dumps(OWNER_KEY))
    dpop = generate_dpop(owner_key, VC)
    print("DPoP:")
    print(dpop.serialize())


if __name__ == '__main__':
    main()
