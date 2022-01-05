import json
import random
import time
import hashlib
from jwcrypto import jwt, jwk
from jwcrypto.common import base64url_decode, base64url_encode

class Prover:
    def generate_valid_dpop(self, owner_key, access_token, alg="ES256"):
        dpop_header = {
        "typ": "dpop+jwt",
        "alg": alg,
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
        return dpop.serialize()

    def generate_invalid_dpop_key(self, owner_key, access_token, alg="ES256"):
        dpop_header = {
        "typ": "dpop+jwt",
        "alg": alg,
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
        return dpop.serialize()

    def generate_invalid_dpop_ath(self, owner_key, access_token, alg="ES256"):
        dpop_header = {
        "typ": "dpop+jwt",
        "alg": alg,
        "jwk": owner_key.export_public(as_dict=True)
        }
        dpop_claims = {
            "jti": "-BwC3ESc6acc2lTc",
            "htm": "GET",
            "htu": "https://remote.cloud/zerocorp",
            "iat": 1562262616,
            "ath": base64url_encode(hashlib.sha512(access_token.encode('utf-8')).digest())
        }
        dpop = jwt.JWT(header=dpop_header, claims=dpop_claims)
        dpop.make_signed_token(owner_key)
        return dpop.serialize()

    def generate_invalid_dpop_iat(self, owner_key, access_token, alg="ES256"):
        dpop_header = {
        "typ": "dpop+jwt",
        "alg": alg,
        "jwk": owner_key.export_public(as_dict=True)
        }
        dpop_claims = {
            "jti": "-BwC3ESc6acc2lTc",
            "htm": "GET",
            "htu": "https://remote.cloud/zerocorp",
            "iat": 0,
            "ath": base64url_encode(hashlib.sha256(access_token.encode('utf-8')).digest())
        }
        dpop = jwt.JWT(header=dpop_header, claims=dpop_claims)
        dpop.make_signed_token(owner_key)
        return dpop.serialize()

    def generate_invalid_dpop_typ(self, owner_key, access_token, alg="ES256"):
        dpop_header = {
        "typ": "dpop",
        "alg": alg,
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
        return dpop.serialize()

    def generate_invalid_dpop_alg(self, owner_key, access_token):
        dpop_header = {
        "typ": "dpop+jwt",
        "alg": None,
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
        return dpop.serialize()

    def generate_invalid_dpop_htm(self, owner_key, access_token, alg="ES256"):
        dpop_header = {
        "typ": "dpop+jwt",
        "alg": alg,
        "jwk": owner_key.export_public(as_dict=True)
        }
        dpop_claims = {
            "jti": "-BwC3ESc6acc2lTc",
            "htm": "POST",
            "htu": "https://remote.cloud/zerocorp",
            "iat": 1562262616,
            "ath": base64url_encode(hashlib.sha256(access_token.encode('utf-8')).digest())
        }
        dpop = jwt.JWT(header=dpop_header, claims=dpop_claims)
        dpop.make_signed_token(owner_key)
        return dpop.serialize()

    

if __name__ == '__main__':
    '''
    >>> key = jwk.JWK.generate(kty='EC', crv='P-256')
    >>> print (key.export(as_dict=True))
    '''
    key = {'kty': 'EC', 'crv': 'P-256', 'x': 'nVpBMFBRaBxTJ18Xjvu49mAPFdjL1KPwhp7NZcGG06U', 'y': 'qwbPL4x3YXoh6GiuKpYvFZ2QocpimTXjIZIW8UMBh78', 'd': 'Jqjv6ns_eEIG-v1CTfZn5CsvJ1g8Q_j0QXRlZvZA4uY'}
    owner_key = jwk.JWK.from_json(json.dumps(key)) 
    prover = Prover()
    print (prover.generate_valid_dpop(owner_key, "this is a test token"))