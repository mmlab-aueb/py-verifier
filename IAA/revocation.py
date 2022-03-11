import requests
import json
import base64
from jwt_pep import jwt_pep


class Revocation:

    def __init__(self):
        self.jwt_pep = jwt_pep()

    def check_status_from_issuer(self, issuer, bitindex,trusted_issuers):
        rev_cred = requests.get(issuer).text
        valid_jwt, ver_output = self.jwt_pep.verify_jwt(token=rev_cred, 
                    trusted_issuers  = trusted_issuers)
        if not valid_jwt:
            print("Could not verify revocation list", ver_output)
            return False
        jwt_vc = json.loads(ver_output)
        rev_list = jwt_vc['vc']['credentialSubject']['encodedList']
        rev_list_bytes = base64.b64decode(rev_list)
        index = int(bitindex // 8);
        bit = int(bitindex % 8);
        status = (rev_list_bytes[index] >> bit) & 1
        return status == 0
        

if __name__ == '__main__':
    revocation = Revocation()
    print(revocation.check_status_from_issuer("https://issuer.mmlab.edu.gr/oauth2/status",8))