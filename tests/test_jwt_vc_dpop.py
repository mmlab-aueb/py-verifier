import pytest
import requests
import json
from issuer import Issuer
from prover import Prover
from jwcrypto import jwk 


class TestJWTDPoP:
    
    def test_valid_dpop(self):
        key = {'kty': 'EC', 'crv': 'P-256', 'x': 'nVpBMFBRaBxTJ18Xjvu49mAPFdjL1KPwhp7NZcGG06U', 'y': 'qwbPL4x3YXoh6GiuKpYvFZ2QocpimTXjIZIW8UMBh78', 'd': 'Jqjv6ns_eEIG-v1CTfZn5CsvJ1g8Q_j0QXRlZvZA4uY'}
        owner_key = jwk.JWK.from_json(json.dumps(key)) 
        token = Issuer().issue_valid_vc_with_cnf(owner_key)
        dpop = Prover().generate_valid_dpop(owner_key, token)
        headers = {'Authorization':'DPoP ' + token, 'Accept': 'application/json', 'dpop':dpop}
        response  = requests.get("http://localhost:9000/secure/jwt-vc-dpop", headers = headers)
        print(response.text)
        assert(response.status_code == 200)

    def test_invalid_dpop_typ(self):
        key = {'kty': 'EC', 'crv': 'P-256', 'x': 'nVpBMFBRaBxTJ18Xjvu49mAPFdjL1KPwhp7NZcGG06U', 'y': 'qwbPL4x3YXoh6GiuKpYvFZ2QocpimTXjIZIW8UMBh78', 'd': 'Jqjv6ns_eEIG-v1CTfZn5CsvJ1g8Q_j0QXRlZvZA4uY'}
        owner_key = jwk.JWK.from_json(json.dumps(key)) 
        token = Issuer().issue_valid_vc_with_cnf(owner_key)
        dpop = Prover().generate_invalid_dpop_typ(owner_key, token)
        headers = {'Authorization':'DPoP ' + token, 'Accept': 'application/json', 'dpop':dpop}
        response  = requests.get("http://localhost:9000/secure/jwt-vc-dpop", headers = headers)
        print(response.text)
        assert(response.status_code == 401)

    '''def test_invalid_dpop_alg(self):
        key = {'kty': 'EC', 'crv': 'P-256', 'x': 'nVpBMFBRaBxTJ18Xjvu49mAPFdjL1KPwhp7NZcGG06U', 'y': 'qwbPL4x3YXoh6GiuKpYvFZ2QocpimTXjIZIW8UMBh78', 'd': 'Jqjv6ns_eEIG-v1CTfZn5CsvJ1g8Q_j0QXRlZvZA4uY'}
        owner_key = jwk.JWK.from_json(json.dumps(key)) 
        token = Issuer().issue_valid_vc_with_cnf(owner_key)
        dpop = Prover().generate_invalid_dpop_alg(owner_key, token)
        headers = {'Authorization':'DPoP ' + token, 'Accept': 'application/json', 'dpop':dpop}
        response  = requests.get("http://localhost:9000/secure/jwt-vc-dpop", headers = headers)
        print(response.text)
        assert(response.status_code == 401)'''

    def test_invalid_dpop_htm(self):
        key = {'kty': 'EC', 'crv': 'P-256', 'x': 'nVpBMFBRaBxTJ18Xjvu49mAPFdjL1KPwhp7NZcGG06U', 'y': 'qwbPL4x3YXoh6GiuKpYvFZ2QocpimTXjIZIW8UMBh78', 'd': 'Jqjv6ns_eEIG-v1CTfZn5CsvJ1g8Q_j0QXRlZvZA4uY'}
        owner_key = jwk.JWK.from_json(json.dumps(key)) 
        token = Issuer().issue_valid_vc_with_cnf(owner_key)
        dpop = Prover().generate_invalid_dpop_htm(owner_key, token)
        headers = {'Authorization':'DPoP ' + token, 'Accept': 'application/json', 'dpop':dpop}
        response  = requests.get("http://localhost:9000/secure/jwt-vc-dpop", headers = headers)
        print(response.text)
        assert(response.status_code == 401)

    '''def test_invalid_dpop_iat(self):
        key = {'kty': 'EC', 'crv': 'P-256', 'x': 'nVpBMFBRaBxTJ18Xjvu49mAPFdjL1KPwhp7NZcGG06U', 'y': 'qwbPL4x3YXoh6GiuKpYvFZ2QocpimTXjIZIW8UMBh78', 'd': 'Jqjv6ns_eEIG-v1CTfZn5CsvJ1g8Q_j0QXRlZvZA4uY'}
        owner_key = jwk.JWK.from_json(json.dumps(key)) 
        token = Issuer().issue_valid_vc_with_cnf(owner_key)
        dpop = Prover().generate_invalid_dpop_iat(owner_key, token)
        headers = {'Authorization':'DPoP ' + token, 'Accept': 'application/json', 'dpop':dpop}
        response  = requests.get("http://localhost:9000/secure/jwt-vc-dpop", headers = headers)
        print(response.text)
        assert(response.status_code == 401)'''

    def test_invalid_dpop_ath(self):
        key = {'kty': 'EC', 'crv': 'P-256', 'x': 'nVpBMFBRaBxTJ18Xjvu49mAPFdjL1KPwhp7NZcGG06U', 'y': 'qwbPL4x3YXoh6GiuKpYvFZ2QocpimTXjIZIW8UMBh78', 'd': 'Jqjv6ns_eEIG-v1CTfZn5CsvJ1g8Q_j0QXRlZvZA4uY'}
        owner_key = jwk.JWK.from_json(json.dumps(key)) 
        token = Issuer().issue_valid_vc_with_cnf(owner_key)
        dpop = Prover().generate_invalid_dpop_ath(owner_key, token)
        headers = {'Authorization':'DPoP ' + token, 'Accept': 'application/json', 'dpop':dpop}
        response  = requests.get("http://localhost:9000/secure/jwt-vc-dpop", headers = headers)
        print(response.text)
        assert(response.status_code == 401)

    def test_invalid_dpop_key(self):
        key = {"kty": "EC", "crv": "P-256", "x": "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74", "y": "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI", "d": "0g5vAEKzugrXaRbgKG0Tj2qJ5lMP4Bezds1_sTybkfk"}
        key1 = {'kty': 'EC', 'crv': 'P-256', 'x': 'nVpBMFBRaBxTJ18Xjvu49mAPFdjL1KPwhp7NZcGG06U', 'y': 'qwbPL4x3YXoh6GiuKpYvFZ2QocpimTXjIZIW8UMBh78', 'd': 'Jqjv6ns_eEIG-v1CTfZn5CsvJ1g8Q_j0QXRlZvZA4uY'}
        owner_key = jwk.JWK.from_json(json.dumps(key)) 
        owner_key1 = jwk.JWK.from_json(json.dumps(key1))
        token = Issuer().issue_valid_vc_with_cnf(owner_key)
        dpop = Prover().generate_invalid_dpop_key(owner_key1, token)
        headers = {'Authorization':'DPoP ' + token, 'Accept': 'application/json', 'dpop':dpop}
        response  = requests.get("http://localhost:9000/secure/jwt-vc-dpop", headers = headers)
        print(response.text)
        assert(response.status_code == 401)

