import pytest
import requests
import json 


class TestJWT:
    def test_valid_authorization_get(self):
        token = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJjbmYiOnsiandrIjp7ImNydiI6IkVkMjU1MTkiLCJrdHkiOiJPS1AiLCJ4IjoiNnZjRkhiem4xc0lORzQtUVlaMUlhaTNkMm1LVTF1MEtZRDNya0tobk1hbyJ9fSwiaXNzIjoiaHR0cHM6Ly96ZXJvLmNvcnAiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vbW0uYXVlYi5nci9jb250ZXh0cy9hY2Nlc3NfY29udHJvbC92MSJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJDYXBhYmlsaXRpZXMiOlsiUmVhZCBJbnZlbnRvcnkiLCJXcml0ZSBJbnZlbnRvcnkiXSwidHlwZSI6WyJDYXBhYmlsaXRpZXMiXX0sImlkIjoiaHR0cHM6Ly93d3cuc29maWUtaW90LmV1L2NyZWRlbnRpYWxzL2V4YW1wbGVzLzEiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIl19fQ.1dVXJhv1hAY7Uhvg_DW553aSXrZYKj-15xxtzTeZXgVkUuq1JP1o6uQbzb_ABBndWPa0HVlue4G3Ulw4RIdlBg"
        headers = {'Authorization':'Bearer ' + token, 'Accept': 'application/json'}
        response  = requests.get("http://localhost:9000/secure/jwt-vc", headers = headers)
        print(response.text)
        assert(response.status_code == 200)

    def test_valid_authorization_with_pem_get(self):
        token = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOjE2Mzc3MTEyOTUsImV4cCI6MTYzNzc5NzY5NSwiaXNzIjoiaHR0cHM6Ly9hcy5jb250cm9sdGhpbmdzLmdyIiwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL21tLmF1ZWIuZ3IvY29udGV4dHMvY2FwYWJpbGl0aWVzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJDYXBhYmlsaXRpZXNDcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImNhcGFiaWxpdGllcyI6eyJSYXNwYmVycnkgUGkiOlsiUkVTVF9BUEkiLCJWSUVXX1NUQVRVUyJdfX19fQ.rZ_hk3z58aVPkME4fa5Ij1E2YSAv4WDprviRDhxrooPb2ExAfmFsyiTAtWmXNoWplw49Ffxf2beoxTRrue6cSg"
        headers = {'Authorization':'Bearer ' + token, 'Accept': 'application/json'}
        response  = requests.get("http://localhost:9000/secure/jwt-vc-pem", headers = headers)
        print(response.text)
        assert(response.status_code == 200)
