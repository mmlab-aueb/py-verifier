import json
import time

from resolver import Resolver
try:
    from jwcrypto import jwt, jwk, jws
    from jsonpath_ng import jsonpath
    from jsonpath_ng.ext import parse
    from jwcrypto.common import base64url_decode
except ImportError:
     print("Couldn't import files required for JWT parsing, if you don't need JWT/JWT-encoded VCs that's OK")

class jwt_pep:
    def verify_jwt(self, token, trusted_issuers, filter=None): 
        try:
            decoded_token = jwt.JWS()
            decoded_token.deserialize(token)
            token_payload = json.loads(decoded_token.objects['payload'].decode())
            # check credential validity times
            now = int(time.time())
            if 'nbf' in token_payload:
                if now < token_payload['nbf']:
                    return False, "Error: Credential is not valid yet"
            if 'exp' in token_payload:
                if now > token_payload['exp']:
                    return False, "Error: Credential has expired"
            # Read the iss claim
            iss = token_payload['iss']
            # Check if iss is trusted
            if (iss not in trusted_issuers): # Not rusted issuer
                return False, "Issuer is not trusted"
            # Retreive the issuer key    
            ver_key = None
            issuer_key_type = trusted_issuers[iss]['issuer_key_type']
            issuer_key = trusted_issuers[iss]['issuer_key']
            if (issuer_key_type == "pem_file"):
                with open(issuer_key, mode='rb') as file: 
                    pem_file = file.read()
                ver_key = jwk.JWK.from_pem(pem_file)
            if (issuer_key_type == "jwt"):
                ver_key = jwk.JWK.from_json(json.dumps(issuer_key))
            if (issuer_key_type == "did"):
                ver_key = Resolver().resolve(issuer_key)
            # Verify the JWS
            decoded_token.verify(ver_key)
            # Check for filters
            if(filter):
                if(not self._filter(json.loads(decoded_token.payload.decode()), filter)):
                    return False, "Filter verification failed" #Filter failed
            return True, decoded_token.payload.decode()
        except Exception as e:
            return False, str(e) #Token cannot be decoded
    
    def verify_dpop(self, dpop_b64, client_key, htu=None, ath=None, lifetime=None):
        """Verifies a DPoP proof. If the verification succeeds it returns
        True and the DPoP as a jwcrypto.jwt . Otherwise it returns False and the exception error

        :param dpop_b64(string): The base64 encoding of the DPoP HTTP header
        :param client_key(dict): The client key encoded as as JWK
        :param htu(string): The value that htu claim of the DPoP should have. If set to None, this check is skipped.
        :param ath(string): The value that ath claim of the DPoP should have. If set to None, this check is skipped.
        :param lifetime(int): The time after iat that a DPoP will be accepted.If set to None, this check is skipped.
        """
        try:
            dpop_b64_header = dpop_b64.split('.')
            dpop_json_header = json.loads(
                base64url_decode(dpop_b64_header[0]).decode('utf-8'))
            dpop_json_claims = json.loads(base64url_decode(dpop_b64_header[1]).decode('utf-8'))
            dpop_key = jwk.JWK.from_json(json.dumps(dpop_json_header['jwk']))
            
            '''
            Perform the checks specified in 
            https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop-04
            '''
            #Check typ, alw, jwk
            #TBD

            #Check jti
            #TBD

            #Check htm
            #TBD

            #Check htu
            #TBD

            #Check iat
            '''
            Be careful, this requires client's and verifier's clocks to be in sync
            '''
            if expires != None:
                now = datetime.datetime.now().timestamp()
                if ("iat" not in dpop_json_claims or dpop_json_claims['iat'] + expires < now):
                    return False, "DPoP has expired"


            #Check ath
            if ath != None and ("ath" not in dpop_json_claims or dpop_json_claims['ath'] != ath):
                return False, "'ath' claim doesn't match with hash of JWT"


            if dpop_key != client_key: # check that key in DPoP header matches with the key in VC
                return False, "DPoP header key doesn't match client_key"

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