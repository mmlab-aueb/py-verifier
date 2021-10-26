try:
    from jwcrypto import jwt, jwk
    from jsonpath_ng import jsonpath
    from jsonpath_ng.ext import parse
except ImportError:
     print("Couldn't import files required for JWT parsing, if you don't need JWT/JWT-encoded VCs that's OK")

class jwt_pep:
    def verify_jwt(self, token=None, signing_key=None, signing_key_type="pem", tokens_expire = True, filter=None, proof=None): 
        try:
            ver_key = None
            if (signing_key_type == "pem"):
                ver_key = jwk.JWK.from_pem(signing_key)
            decoded_token = jwt.JWT(jwt=token, key=ver_key)
            if(filter):
                if(self._filter(decoded_token, filter)):
                    return True, 0
                else:
                    return False, 101 #Filter failed
            return True, 0
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