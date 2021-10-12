from werkzeug.wrappers import Request, Response
from erc721_token import ERC721_token
from jwt_token import JWT_token
from jwcrypto import jwk
from oauth2_dpop import verify_dpop
from jwcrypto.common import base64url_decode

import json
    
class Authorization_Server():
    def __init__(self):
        with open('AS/conf/as.conf') as f:
            self.conf = json.load(f)
        self.erc721    = ERC721_token()
        self.jwt_token = JWT_token()

    def wsgi_app(self, environ, start_response):
        req  = Request(environ)
        form = req.form
        code = 403
        authorized = False
        authenticated = False
        output = 'Invalide or missing input parameters'.encode()
        grant_type        = form.get("grant-type", None)
        auth_code         = form.get("code", None)
        record_erc721     = form.get("erc-721", True)
        dpop              = form.get("DPoP", None)
        if (grant_type == "authorization_code"):
            authorized = True
        if (dpop):
            authenticated, dpopjwt = verify_dpop (dpop, "http://localhost:9001/token")     
        if (authorized and authenticated):
            code = 200
            client_jsonkey =  json.loads(dpopjwt.header)['jwk']
            client_jwk = jwk.JWK.from_json(json.dumps(client_jsonkey))
            token_claims = {
                'iss':'https://mm.aueb.gr',
                'cnf':{
                    'jkt': client_jwk.thumbprint()
                }
            }
            token,claims = self.jwt_token.generate_token(self.conf['as_private_key'], token_claims)
            output = token
            if (record_erc721):
                client_jwk_dict = client_jwk.export(as_dict=True)
                client_public_key_bytes_x= base64url_decode(client_jwk_dict['x'])
                client_public_key_bytes_y= base64url_decode(client_jwk_dict['y'])
                client_public_key_bytes =  client_public_key_bytes_x + client_public_key_bytes_y
                self.erc721.record_erc721(int(claims['jti'],base=16), output, client_public_key_bytes)
    
        response = Response(output, status=code, mimetype='application/json')
        return response(environ, start_response)
    
    def __call__(self, environ, start_response):
        return self.wsgi_app(environ, start_response)

def main(): 
    from werkzeug.serving import run_simple
    app = Authorization_Server()
    run_simple('', 9001, app)

if __name__ == '__main__':
    main()