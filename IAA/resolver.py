from jwcrypto   import  jwk
from jwcrypto.common  import base64url_encode
import requests
import base58
import json

class Resolver:

    def resolve(self,did):
        key_jwk = jwk.JWK()
        if did[4:8] == "self": # self method, has to be fixed
            key = {"kty": "OKP", "crv": "Ed25519"}
            key["x"] = did[9:] # strip 'did:self:'
            key_jwk = key_jwk.from_json(json.dumps(key))
            return key_jwk
        elif did[4:7] == "key": # key method
            key = {"kty": "OKP", "crv": "Ed25519"}
            key["x"] = base64url_encode(base58.b58decode(did[9:])[2:])
            key_jwk = key_jwk.from_json(json.dumps(key))
            return key_jwk
        elif did[4:7] == "web": # web method
            uresolver = 'https://resolver.identity.foundation/1.0/identifiers/' + did
            try:
                result = requests.get(uresolver).json()
                keydict = result['didDocument']['authentication'][0]['publicKeyJwk']
                key_jwk = key_jwk.from_json(json.dumps(keydict))
                return key_jwk
            except:
                raise Exception("Unsupported DID method")
            
        else: # unknown DID method
            raise Exception("Unsupported DID method")

if __name__ == '__main__':
    resolver = Resolver()
    print (resolver.resolve('did:web:did.mmlab.edu.gr:mmlab'))