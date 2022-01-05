from jwcrypto   import  jwk
import json

class DIDWeb:
    def create(self):
        key = jwk.JWK.generate(kty='EC', crv='P-256')
        print (key.export(as_dict=True))
        did_document = {
            "@context": "https://w3id.org/did/v1",
            "id": "did:web:did.mmlab.edu.gr:mmlab",
            "authentication": [{
                "id": "did:web:did.mmlab.edu.gr:mmlab#owner",
                "type": "JsonWebKey2020",
                "publicKeyJwk": key.export_public(as_dict=True)
                }]
            }
        return did_document
        
if __name__ == '__main__':
    didweb = DIDWeb()
    print (json.dumps(didweb.create()))