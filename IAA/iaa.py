from werkzeug.wrappers       import Request, Response
from werkzeug.datastructures import Headers
from jwt_pep                 import jwt_pep
from http_proxy              import http_proxy
from jwcrypto.common         import base64url_decode
from jwcrypto                import jwt, jwk

import json
import sys
import asyncio
import base64

class IAAHandler():
    def __init__(self):
        with open('conf/iaa.conf') as f:
            try:
                self.conf = json.load(f)
            except json.decoder.JSONDecodeError as error:
                print(error)
                sys.exit("Cannot parse the configuration file")
        self.jwt_pep = jwt_pep()
        self.http_proxy = http_proxy()

    def wsgi_app(self, environ, start_response):
        req      = Request(environ)
        path     = environ.get('PATH_INFO')
        code     = 401
        resource = {}
        output   = 'Invalid or missing input parameters'
        output_header = {}
        auth    = req.headers.get('Authorization')
        if (path in self.conf['resources']):
            resource = self.conf['resources'][path]
        elif ('default' in self.conf['resources']):
            resource = self.conf['resources']["default"]
        is_client_authorized = False
        ver_output = "Forbidden!"
        if ('authorization' in resource and auth):
            auth_type, auth_grant = auth.split(" ",1)
            #*********JWT***********
            if (resource['authorization']['type'] == "jwt-vc" and auth_type == "Bearer"):
                filter = None
                if ('issuer_key' not in resource['authorization']):
                    with open(resource['authorization']['issuer_key_file'], mode='rb') as file: 
                        resource['authorization']['issuer_key'] = file.read()
                if ('filters' in resource['authorization']):
                    filter = resource['authorization']['filters']
                is_client_authorized, ver_output = self.jwt_pep.verify_jwt(token=auth_grant, 
                    issuer_key  = resource['authorization']['issuer_key'], 
                    issuer_key_type = resource['authorization']['issuer_key_type'],
                    tokens_expire = resource['authorization']['tokens_expire'], 
                    filter = filter)

            #*********JWT with DPoP (eSSIF)***********
            if (resource['authorization']['type'] == "jwt-vc-dpop" and auth_type == "DPoP"):
                step1 = False
                step2 = False
                step3 = False
                filter = None
                # Step 1: Validate VC
                # The VC is just a signed JWT
                if ('issuer_key' not in resource['authorization']):
                    with open(resource['authorization']['issuer_key_file'], mode='rb') as file: 
                        resource['authorization']['issuer_key'] = file.read()
                if ('filters' in resource['authorization']):
                    filter = resource['authorization']['filters']
                step1, ver_output = self.jwt_pep.verify_jwt(token=auth_grant, 
                    issuer_key  = resource['authorization']['issuer_key'], 
                    issuer_key_type = resource['authorization']['issuer_key_type'],
                    tokens_expire = resource['authorization']['tokens_expire'], 
                    filter = filter)
                
                # Step 2: Extract client public key
                client_key = jwk.JWK()
                if (step1):
                    try:
                        jwt_vc = json.loads(ver_output)
                        client_key.from_json(json.dumps(jwt_vc['cnf']['jwk']))
                        step2 = True
                    except:
                        step2 = False    

                # Step 3: Validate DPoP
                if (step1 and step2):
                    dpop = req.headers.get('dpop')
                    step3, ver_output = self.jwt_pep.verify_dpop(dpop)

                if (step1 and step2 and step3):
                   is_client_authorized = True

        elif('authorization' not in resource):
            is_client_authorized = True
        if (is_client_authorized):
            if ('proxy' in  resource):
                code, output = self.http_proxy.forward(environ, resource['proxy']['proxy_pass'], resource['proxy'].get('header_rewrite'))
            else:
                code = "200"
                output = "Authorized request!"
        else:
            output = ver_output
        response = Response(output.encode(), status=code, mimetype='application/json')
        if output_header:
            for key,value in output_header.items():
                response.headers.add(key, value)
        return response(environ, start_response)
        
    def __call__(self, environ, start_response):
        return self.wsgi_app(environ, start_response)

def create_app():
    app = IAAHandler()
    return app

def main(): 
    from werkzeug.serving import run_simple
    app = create_app()
    run_simple('localhost', 9000, app)

if __name__ == '__main__':
    main()
