import json
try:
    from jwcrypto import jwt, jwk, jws
    from jsonpath_ng import jsonpath
    from jsonpath_ng.ext import parse
    from jwcrypto.common import base64url_decode
except ImportError:
     print("Couldn't import files required for JWT parsing, if you don't need JWT/JWT-encoded VCs that's OK")

class jwt_pep:
    def verify_jwt(self, token=None,issuer_key=None,issuer_key_type="pem", tokens_expire = True, filter=None, proof=None): 
        try:
            ver_key = None
            if (issuer_key_type == "pem"):
                ver_key = jwk.JWK.from_pem(issuer_key)
            if (issuer_key_type == "jwt"):
                ver_key = jwk.JWK.from_json(json.dumps(issuer_key))
            decoded_token = jwt.JWS()
            decoded_token.deserialize(token)
            decoded_token.verify(ver_key)
            '''
            if(filter):
                if(self._filter(decoded_token, filter)):
                    return True, "0"
                else:
                    return False, "101" #Filter failed
            '''
            return True, decoded_token.payload.decode()
        except Exception as e:
            print("Error" + str(e))
            return False, str(e) #Token cannot be decoded
    
    def verify_dpop(self, dpop_b64, htu=None):
        """Verifies a DPoP proof. If the verification succeeds it returns
        True and the DPoP as a jwcrypto.jwt . Otherwise it returns False and the exception error

        :param dpop_b64(string): The base64 encoding of the DPoP HTTP header
        :param client_key(dict): The client key encoded as as JWK
        :param htu(string): The value that htu claim of the DPoP should have
        """
        try:
            dpop_b64_header = dpop_b64.split('.')
            dpop_json_header = json.loads(
                base64url_decode(dpop_b64_header[0]).decode('utf-8'))
            dpop_key = jwk.JWK.from_json(json.dumps(dpop_json_header['jwk']))
            dpop_verified = jwt.JWT(jwt=dpop_b64, key=dpop_key)
            return True, dpop_verified
        except Exception as e:
            print("Error" + str(e))
            return False, str(e) #Token cannot be decoded

    def _filter(self, json_obj, filters):  
        for filter in filters:
            jsonpath_expr = parse(filter[0])
            found = False
            for match in jsonpath_expr.find(json_obj):
                if len(filter) == 2 and isinstance(filter[1], list):
                    if match.value in filter[1]:
                        found = True
                elif len(filter) == 2:
                    if match.value == filter[1]:
                        found = True
                else: #no value is required
                    found = True
            if not found:
                return False 
        return True