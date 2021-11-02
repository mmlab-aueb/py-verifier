"""It includes functions for generating and verifying OAuth 2.0
DPoP based on https://tools.ietf.org/html/draft-fett-oauth-dpop-04
"""
import json
import random
import time
from jwcrypto import jwt, jwk
from jwcrypto.common import base64url_decode


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


def generate_dpop(owner_key):
    """
    Generates a DPoP proof

    :param owner_key(jwk.JWK the owner key pair)
    """
    dpop_header = {
        "typ": "dpop+jwt",
        "alg": "EdDSA",
        "jwk": owner_key.export_public(as_dict=True)
    }
    dpop_claims = {
        "jti": "-BwC3ESc6acc2lTc",
        "htm": "POST",
        "htu": "https://server.example.com/token",
        "iat": 1562262616
    }
    dpop = jwt.JWT(header=dpop_header, claims=dpop_claims)
    dpop.make_signed_token(owner_key)
    return dpop


def main():
    '''
    >>> key = jwk.JWK.generate(kty='OKP', crv='Ed25519')
    >>> print (key.export(as_dict=True))
    '''
    OWNER_KEY = {'kty': 'OKP', 'crv': 'Ed25519', 'x': '6vcFHbzn1sING4-QYZ1Iai3d2mKU1u0KYD3rkKhnMao',
                 'd': '_TTTDArI9aYlafDiXzucKt_AMmrr7uDnyNEEqGTb-Mk'}
    ISSUER_KEY = {'kty': 'OKP', 'crv': 'Ed25519', 'x': 's_juSSVh2bQgeAZjBl3Tn7ddO8Auovlj00veVlOZqqA',
                  'd': 'gjst4ZqUvUfKVTGewO2EmiDdzs2YKHBPGCB9YorCa8E'}
    JTW_VC_CLAIMS = {
        "iss": "https://zero.corp",
        "vc": {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://mm.aueb.gr/contexts/access_control/v1"
            ],
            "id": "https://www.sofie-iot.eu/credentials/examples/1",
            "type": ["VerifiableCredential"],
            "credentialSubject": {
                "type": ["Capabilities"],
                "Capabilities": [
                    "Read Inventory",
                    "Write Inventory"
                ]
            }
        }
    }
    JTW_VC_HEADER = {
        "alg": "EdDSA",
        "typ": "JWT",
    }
    owner_key = jwk.JWK.from_json(json.dumps(OWNER_KEY))
    dpop = generate_dpop(owner_key)
    print(dpop.serialize())

    issuer_key = jwk.JWK.from_json(json.dumps(ISSUER_KEY))
    jwt_vc = jwt.JWT(header=JTW_VC_HEADER, claims=JTW_VC_CLAIMS)
    jwt_vc.make_signed_token(issuer_key)
    print(jwt_vc.serialize())


if __name__ == '__main__':
    main()
