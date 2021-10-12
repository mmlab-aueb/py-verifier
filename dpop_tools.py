import json
import random
import time

from jwcrypto import jwt, jwk
from jwcrypto.common import base64url_decode

client_key = jwk.JWK.generate(kty='EC', crv='secp256k1')


dpop_header = {
     "typ":"dpop+jwt",
     "alg":"ES256K",
     "jwk": client_key.export_public(as_dict=True)
}
dpop_claims = {
     "jti":hex(random.getrandbits(256)),
     "htm":"POST",
     "htu":"https://server.example.com/token",
     "iat": int(time.time())
}


dpop = jwt.JWT(header = dpop_header, claims = dpop_claims)
dpop.make_signed_token(client_key)
print(dpop.serialize())
print(len(dpop.serialize()))
start = time.time()
dpop_b64 = dpop.serialize().split('.')
dpop_b64_header = json.loads(base64url_decode(dpop_b64[0]).decode('utf-8'))
#print(dpop_b64_header['jwk'])
dpop_key = jwk.JWK.from_json(json.dumps(dpop_b64_header['jwk']))
try: 
     dpop_verified = jwt.JWT(jwt=dpop.serialize(), key=dpop_key)
     end = time.time()
     print(end - start)
     print(json.loads(dpop_verified.header)['jwk'])
except:
     print("Error in decoding")




