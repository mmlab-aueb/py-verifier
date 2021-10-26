from werkzeug.wrappers       import Request, Response
from werkzeug.datastructures import Headers
from jwt_pep                 import jwt_pep
from w3c_vc_pep              import w3c_vc_pep
from pop_pep                 import pop_pep
from http_proxy              import http_proxy

import json
import sys
import asyncio
import requests
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
        self.w3c_vc_pep = w3c_vc_pep()
        self.http_proxy = http_proxy()
        self.pop_pep    = pop_pep()

    def wsgi_app(self, environ, start_response):
        req      = Request(environ)
        path     = environ.get('PATH_INFO')
        code     = 401
        resource = {}
        output   = 'Invalide or missing input parameters'
        output_header = {}
        auth    = req.headers.get('Authorization')
        if (path in self.conf['resources']):
            resource = self.conf['resources'][path]
        elif ('default' in self.conf['resources']):
            resource = self.conf['resources']["default"]
        is_client_authorized = False
        ver_output = "0"
        if ('authorization' in resource and auth):
            auth_type, auth_grant = auth.split(" ",1)
            #*********W3C-VC***********
            if (resource['authorization']['type'] == "w3c-vc" and auth_type == "Bearer-W3C-VC"):
                if ('signing_key' not in resource['authorization']):
                    with open(resource['authorization']['signing_key_file'], mode='rb') as file: 
                        resource['authorization']['signing_key'] = file.read()
                result, ver_output = self.w3c_vc_pep.verify_w3c_vc(vc=base64.urlsafe_b64decode(auth_grant).decode(), 
                    signing_key  = resource['authorization']['signing_key'],  
                    filter= resource['authorization']['filters'])
                if (result == True):
                    is_client_authorized = True

            #*********JWT***********
            if (resource['authorization']['type'] == "jwt" and auth_type == "Bearer"):
                if ('signing_key' not in resource['authorization']):
                    with open(resource['authorization']['signing_key_file'], mode='rb') as file: 
                        resource['authorization']['signing_key'] = file.read()
                result, ver_output = self.jwt_pep.verify_jwt(token=auth_grant, 
                    signing_key  = resource['authorization']['signing_key'], 
                    tokens_expire = resource['authorization']['tokens_expire'], 
                    filter= resource['authorization']['filters'])
                if (result == True):
                    is_client_authorized = True

            #*********JWT-encded VC with DPoP (eSSIF)***********
            if (resource['authorization']['type'] == "jwt-vc-dpop" and auth_type == "DPoP"):
                step1 = False
                step2 = False
                step3 = False
                # Step 1: Validate VC
                # The VC is just a signed JWT
                if ('signing_key' not in resource['authorization']):
                    with open(resource['authorization']['signing_key_file'], mode='rb') as file: 
                        resource['authorization']['signing_key'] = file.read()
                step1, ver_output = self.jwt_pep.verify_jwt(token=auth_grant, 
                    signing_key  = resource['authorization']['signing_key'], 
                    signing_key_type = "pem",
                    tokens_expire = resource['authorization']['tokens_expire'], 
                    filter= resource['authorization']['filters'])
                
                # Step 2: Extract client public key
                if (step1):
                    step2 = True

                # Step 3: Validate DPoP
                if (step1 and step2):
                    step3 = True

                if (step1 and step2 and step3):
                   is_client_authorized = True

        elif('authorization' not in resource):
            is_client_authorized = True
        if (is_client_authorized):
            if ('proxy' in  resource):
                code, output = self.http_proxy.forward(environ, resource['proxy']['proxy_pass'], resource['proxy'].get('header_rewrite'))
            else:
                code = 200
                output = "OK"
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
    run_simple('', 9000, app)

if __name__ == '__main__':
    main()
