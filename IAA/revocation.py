import requests
import json
import base64
from jwcrypto import  jwt, jws


class Revocation:

    def check_status_from_issuer(self, issuer, bitindex):
        rev_cred = requests.get(issuer).text
        decoded_token = jwt.JWS()
        decoded_token.deserialize(rev_cred)
        rev_cred_payload = json.loads(decoded_token.objects['payload'].decode())
        rev_list = rev_cred_payload['RevocationList']
        rev_list_bytes = base64.b64decode(rev_list)
        index = int(bitindex // 8);
        bit = int(bitindex % 8);
        status = (rev_list_bytes[index] >> bit) & 1
        return status
        

if __name__ == '__main__':
    revocation = Revocation()
    print(revocation.check_status_from_issuer("https://issuer.mmlab.edu.gr/oauth2/status",8))