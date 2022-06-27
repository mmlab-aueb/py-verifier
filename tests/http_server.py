import os
import http.server
import socketserver
import json
from http import HTTPStatus


class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        message= {
            "owner": "Device1-admin",
            "measurements":{
                "temperature":"30oC",
                "humidity":"60%"
            }
        }
        self.send_response(HTTPStatus.OK)
        self.end_headers()
        self.wfile.write(json.dumps(message).encode())

    def do_PUT(self):
        self.send_response(HTTPStatus.OK)
        self.end_headers()
        self.wfile.write(b'Hello world from PUT')

    def do_POST(self):
        self.send_response(HTTPStatus.OK)
        self.end_headers()
        self.wfile.write(b'Hello world from POST')

address = os.getenv('HTTP_SERVER_ADDRESS', 'localhost')
port = int(os.getenv('HTTP_SERVER_PORT', 8080))
print("\n * Protected resource on http://" + address + ":" + str(port) + "/")
httpd = socketserver.TCPServer((address, port), Handler)
httpd.serve_forever()
