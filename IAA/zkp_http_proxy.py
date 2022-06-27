from werkzeug.wrappers import Request, Response
from werkzeug.datastructures import Headers
from prover import Prover
import requests
import json


class zkp_http_proxy:
    
    def forward(self, environ, target, frame={}, header_rewrite = None):
        frame ={
            "measurements":{
                "temperature":"",
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
        full_message = response.text
        framed_message_dict = bbs_prover._frame_message(json.loads(full_message), frame)
        output = json.dumps(framed_message_dict)
        headers = response.headers
        return code, output, headers