from werkzeug.wrappers import Request, Response
from werkzeug.datastructures import Headers
from prover import Prover
import requests
import json
import base64


class zkp_http_proxy:
    
    def forward(self, environ, target, header_rewrite = None):
        req      = Request(environ)
        
        frame ={
            "measurements": {
                "*":{
                    "field":req.args['field'],
                    "values":{
                        "*":{
                            "time":"",
                            "value":""
                        }
                    }
                }
            }
        }
        bbs_prover = Prover()
        path    = environ.get('PATH_INFO')
        req     = Request(environ)
        query   = req.query_string.decode()
        accept  = req.headers.get('Accept')
        content = req.headers.get('Content-Type')
        headers = {}
        if(accept):
            headers['Accept'] = accept
        if(content):
            headers['Content-Type'] = content
        if(header_rewrite):
            headers.update(header_rewrite)
        if (req.method == "GET"):
            response  = requests.get(target + path +"?" + query, headers = headers)
        elif (req.method == "PUT"): 
            put_data = req.data
            response  = requests.put(target + path, headers = headers, data = put_data.decode())
        elif (req.method == "POST"): 
            post_data = req.data
            response  = requests.post(target + path, headers = headers, data = post_data.decode())
        code = response.status_code
        full_message = response.text.rsplit(".", 1)
        payload = full_message[0]
        signature = full_message[1]
        bbs_public_key = 'gh9/xep0FZmatNY1oQgQDDR3TFi6ZgAnXlaRt60Lm4fu0iGJT1+4t69EpHvGG0mqAv1CPIor6G50MzzPzC1sMUGwurGGMnSiUVkFpM6Fs3PnI/QQIsIkb+J6YlMmPBe5'
        print("Received: " , json.dumps(json.loads(payload), indent=3))
        claims, revealed_message, zkp = bbs_prover.generate_zkp(public_key=base64.b64decode(bbs_public_key), message=payload, frame=json.dumps(frame), signature=base64.b64decode(signature))
        output = revealed_message + "." + base64.b64encode(zkp).decode() + "." + str(claims)
        headers = response.headers
        return code, output, headers