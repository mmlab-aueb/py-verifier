import pytest
import requests
import json 

'''
Tests VCs issued by https://issuer.mmlab.edu.gr
'''

class TestJWT:
    def test_valid_authorization_get(self):
        token = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5tbWxhYi5lZHUuZ3IiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vbW0uYXVlYi5nci9jb250ZXh0cy9jYXBhYmlsaXRpZXMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIkNhcGFiaWxpdGllc0NyZWRlbnRpYWwiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiY2FwYWJpbGl0aWVzIjp7IkNsb3VkIHN0b3JhZ2UiOlsiRkxfUkVBRCJdfX19fQ.wlgCx4P3bhrJqBeV5e186kdfFwWCRR5goo5GRdJxSF1ui5vlEW60FedJHV_PY4SBBn3RS63-yeyfPuOuj1j9lw"
        headers = {'Authorization':'Bearer ' + token, 'Accept': 'application/json'}
        response  = requests.get("http://localhost:9000/mmlab/jwt-vc", headers = headers)
        print(response.text)
        assert(response.status_code == 200)

    def test_valid_authorization_with_pem_get(self):
        token = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5tbWxhYi5lZHUuZ3IiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vbW0uYXVlYi5nci9jb250ZXh0cy9jYXBhYmlsaXRpZXMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIkNhcGFiaWxpdGllc0NyZWRlbnRpYWwiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiY2FwYWJpbGl0aWVzIjp7IkNsb3VkIHN0b3JhZ2UiOlsiRkxfUkVBRCJdfX19fQ.wlgCx4P3bhrJqBeV5e186kdfFwWCRR5goo5GRdJxSF1ui5vlEW60FedJHV_PY4SBBn3RS63-yeyfPuOuj1j9lw"
        headers = {'Authorization':'Bearer ' + token, 'Accept': 'application/json'}
        response  = requests.get("http://localhost:9000/mmlab/jwt-vc-pem", headers = headers)
        print(response.text)
        assert(response.status_code == 200)

    def test_valid_authorization_post(self):
        token = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5tbWxhYi5lZHUuZ3IiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vbW0uYXVlYi5nci9jb250ZXh0cy9jYXBhYmlsaXRpZXMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIkNhcGFiaWxpdGllc0NyZWRlbnRpYWwiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiY2FwYWJpbGl0aWVzIjp7IkNsb3VkIHN0b3JhZ2UiOlsiRkxfUkVBRCJdfX19fQ.wlgCx4P3bhrJqBeV5e186kdfFwWCRR5goo5GRdJxSF1ui5vlEW60FedJHV_PY4SBBn3RS63-yeyfPuOuj1j9lw"
        headers = {'Authorization':'Bearer ' + token, 'Accept': 'application/json', 'Content-Type': 'application/json'}
        data = {'on': False}
        response  = requests.post("http://localhost:9000/mmlab/jwt-vc", headers = headers, data = json.dumps(data))
        print(response.text)
        assert(response.status_code == 200)
