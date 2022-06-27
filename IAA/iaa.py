from werkzeug.wrappers       import Request, Response
from werkzeug.datastructures import Headers
from jwt_pep                 import jwt_pep
from http_proxy              import http_proxy
from jwcrypto.common         import base64url_decode, base64url_encode
from jwcrypto                import jwt, jwk
from resolver                import Resolver
from revocation              import Revocation

import os
import json
import sys
import asyncio
import base64
import hashlib
import re

class IAAHandler():
    def __init__(self):
        conf_file = os.getenv('IAA_CONF_FILE', 'conf/iaa.conf')
        with open(conf_file) as f:
            try:
                self.conf = json.load(f)
            except json.decoder.JSONDecodeError as error:
                print(error)
                sys.exit("Cannot parse the configuration file")
        self.jwt_pep = jwt_pep()
        self.http_proxy = http_proxy()
        self.resolver = Resolver()
        self.revocation = Revocation()

    def wsgi_app(self, environ, start_response):
        req      = Request(environ)
        path     = environ.get('PATH_INFO')
        code     = 401
        resource = {}
        output   = 'Invalid or missing input parameters'
        output_header = {}
        headers = {}
        auth    = req.headers.get('Authorization')
        if (path in self.conf['resources']):
            resource = self.conf['resources'][path]
        elif ('default' in self.conf['resources']):
            resource = self.conf['resources']["default"]
        is_client_authorized = False
        ver_output = "Forbidden!"
        if ('authorization' in resource and auth):
            auth_type, auth_grant = auth.split(" ",1)

            #*********JWT encoded VC***********
            if ((resource['authorization']['type'] == "jwt-vc" and auth_type == "Bearer") or 
                (resource['authorization']['type'] == "jwt-vc-dpop" and auth_type == "DPoP")):
                step1 = False # Validate VC
                step2 = False # Validate DPoP
                
                # Step 1: Validate VC
                # The VC is just a signed JWT
                filter = None
                trusted_issuers  = resource['authorization']['trusted_issuers']
                if ('filters' in resource['authorization']):
                    # Replace arguments in filters with request paramenters
                    for filter in resource['authorization']['filters']:
                        for i, item in enumerate(filter):
                            for x in re.findall(r'#[a-zA-Z]+',item):
                                filter[i] = item.replace(x, req.args[x[1:]])
                    filter = resource['authorization']['filters']
                step1, ver_output = self.jwt_pep.verify_jwt(token=auth_grant, 
                    trusted_issuers  = trusted_issuers,  
                    filter = filter)
                if step1: # The VC is valid, check if it is revoked
                    jwt_vc = json.loads(ver_output)
                    if "credentialStatus" in jwt_vc["vc"]: #There is revocation information
                        step1 = self.revocation.check_status_from_issuer(
                            jwt_vc["vc"]["credentialStatus"]["statusListCredential"],
                            int(jwt_vc["vc"]["credentialStatus"]["statusListIndex"]),
                            trusted_issuers)
                        if not step1:
                            ver_output = "VC has been revoked"
                
                # Step 2: Verify proof-of-possession if necessary
                if (step1 and auth_type == "Bearer"):  # We do not use DPoP
                    step2 = True
                if (step1 and auth_type == "DPoP"):
                    client_key = jwk.JWK()
                    try:
                        jwt_vc = json.loads(ver_output)
                        if ("cnf" in jwt_vc):
                            client_key = jwk.JWK.from_json(json.dumps(jwt_vc['cnf']['jwk']))
                        elif ("sub" in jwt_vc):
                            client_key = self.resolver.resolve(jwt_vc['sub'])
                        else:
                            raise Exception("No valid client key")
                        dpop = req.headers.get('dpop')
                        ath=base64url_encode(hashlib.sha256(auth_grant.encode('utf-8')).digest())
                        step2, ver_output = self.jwt_pep.verify_dpop(dpop,client_key, req.method, ath=ath)
                    except Exception as e:
                        print("Error in verifying DPoP: ", str(e))
                        step2 = False    

                if (step1 and step2 ):
                   is_client_authorized = True

        elif('authorization' not in resource):
            is_client_authorized = True
        if (is_client_authorized):
            if ('proxy' in  resource):
                code, output, headers = self.http_proxy.forward(environ, resource['proxy']['proxy_pass'], resource['proxy'].get('header_rewrite'))
            elif ('zkp_proxy' in  resource):
                # Unoptimized
                from zkp_http_proxy import zkp_http_proxy
                self.zkp_http_proxy = zkp_http_proxy()
                code, output, headers = self.zkp_http_proxy.forward(environ, resource['zkp_proxy']['proxy_pass'], resource['zkp_proxy'].get('header_rewrite'))
            else:
                code = "200"
                output = "Authorized request!"
        else:
            output = ver_output
        if not 'Content-Type' in headers:
            headers['Content-Type'] = "text/html"
        response = Response(output.encode(), status=code, mimetype=headers['Content-Type'])
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
    address = os.getenv('IAA_ADDRESS', 'localhost')
    port = int(os.getenv('IAA_PORT', 9000))
    run_simple(address, port, app)

if __name__ == '__main__':
    main()
