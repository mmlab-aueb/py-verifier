import json
import time
from jwcrypto import jwt, jwk
from jwcrypto.common import base64url_decode, base64url_encode
import base58

class Issuer:
    
    def __init__(self):
        '''
        >>> key = jwk.JWK.generate(kty='EC', crv='P-256')
        >>> print (key.export(as_dict=True))
        '''
        key_dict = {'kty': 'EC', 'crv': 'P-256', 'x': 'z30WuxpsPow8KpH0N93vW24nA0HD48_MluqgdEUvtU4', 'y': 'VcKco12BZFPu5HU2LBLotTD9NitdlNxnBLngD-eTapM', 'd': 'UCe_iiyGTQf13KyLPhLgjVCT3gSx4APgNSbS7uyLxN8'}
        self.key = jwk.JWK.from_json(json.dumps(key_dict))

    def issue_valid_vc(self):
        jwt_header = {
            "typ": "jwt",
            "alg": "ES256",
            "jwk":  self.key.export_public(as_dict=True)
        }
        jwt_claims = {
            "iss": "http://testscript",
            "aud": "https://zero.cloud",
            "vc": {
                "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://mm.aueb.gr/contexts/capabilities/v1"
                ],
                "type": ["VerifiableCredential","CapabilitiesCredential"],
                "credentialSubject": {
                    "capabilities": {
                        "https://zero.cloud": ["FL_READ", "FL_WRITE"]
                    }
                }
            }
        }
        vc = jwt.JWT(header=jwt_header, claims=jwt_claims)
        vc.make_signed_token( self.key)
        return vc.serialize()
    
    def issue_valid_vc_2(self):
        jwt_header = {
            "typ": "jwt",
            "alg": "ES256",
            "jwk":  self.key.export_public(as_dict=True)
        }
        jwt_claims = {
            "iss": "http://testscript",
            "aud": "https://zero.cloud",
            "vc": {
                "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://mm.aueb.gr/contexts/capabilities/v1"
                ],
                "type": ["VerifiableCredential","CapabilitiesCredential"],
                "credentialSubject": {
                    "capabilities": {
                        "device1": ["I1", "I2"]
                    }
                }
            }
        }
        vc = jwt.JWT(header=jwt_header, claims=jwt_claims)
        vc.make_signed_token( self.key)
        return vc.serialize()
    
    def issue_valid_vc_with_cnf(self, owner_key):
        jwt_header = {
            "typ": "jwt",
            "alg": "ES256",
            "jwk":  self.key.export_public(as_dict=True)
        }
        jwt_claims = {
            "iss": "http://testscript",
            "aud": "https://zero.cloud",
            "cnf": {
                "jwk":owner_key.export_public(as_dict=True)
            },
            "vc": {
                "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://mm.aueb.gr/contexts/capabilities/v1"
                ],
                "type": ["VerifiableCredential","CapabilitiesCredential"],
                "credentialSubject": {
                    "capabilities": {
                        "https://zero.cloud": ["FL_READ", "FL_WRITE"]
                    }
                }
            }
        }
        vc = jwt.JWT(header=jwt_header, claims=jwt_claims)
        vc.make_signed_token( self.key)
        return vc.serialize()
    
    def issue_valid_vc_with_sub(self, owner_did):
        jwt_header = {
            "typ": "jwt",
            "alg": "ES256",
            "jwk":  self.key.export_public(as_dict=True)
        }
        jwt_claims = {
            "iss": "http://testscript",
            "aud": "https://zero.cloud",
            "sub": owner_did,
            "vc": {
                "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://mm.aueb.gr/contexts/capabilities/v1"
                ],
                "type": ["VerifiableCredential","CapabilitiesCredential"],
                "credentialSubject": {
                    "capabilities": {
                        "https://zero.cloud": ["FL_READ", "FL_WRITE"]
                    }
                }
            }
        }
        vc = jwt.JWT(header=jwt_header, claims=jwt_claims)
        vc.make_signed_token( self.key)
        return vc.serialize()

    def issue_valid_vc_with_exp(self):
        jwt_header = {
            "typ": "jwt",
            "alg": "ES256",
            "jwk":  self.key.export_public(as_dict=True)
        }
        jwt_claims = {
            "iss": "http://testscript",
            "aud": "https://zero.cloud",
            "exp": int(time.time()) + 600, #expires in 10 min
            "vc": {
                "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://mm.aueb.gr/contexts/capabilities/v1"
                ],
                "type": ["VerifiableCredential","CapabilitiesCredential"],
                "credentialSubject": {
                    "capabilities": {
                        "https://zero.cloud": ["FL_READ", "FL_WRITE"]
                    }
                }
            }
        }
        vc = jwt.JWT(header=jwt_header, claims=jwt_claims)
        vc.make_signed_token( self.key)
        return vc.serialize()

    def issue_expired(self):
        jwt_header = {
            "typ": "jwt",
            "alg": "ES256",
            "jwk":  self.key.export_public(as_dict=True)
        }
        jwt_claims = {
            "iss": "http://testscript",
            "aud": "https://zero.cloud",
            "exp": int(time.time()) - 600, #expired 10 min ago
            "vc": {
                "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://mm.aueb.gr/contexts/capabilities/v1"
                ],
                "type": ["VerifiableCredential","CapabilitiesCredential"],
                "credentialSubject": {
                    "capabilities": {
                        "https://zero.cloud": ["FL_READ", "FL_WRITE"]
                    }
                }
            }
        }
        vc = jwt.JWT(header=jwt_header, claims=jwt_claims)
        vc.make_signed_token( self.key)
        return vc.serialize()
    
    def issue_without_aud(self):
        jwt_header = {
            "typ": "jwt",
            "alg": "ES256",
            "jwk":  self.key.export_public(as_dict=True)
        }
        jwt_claims = {
            "iss": "http://testscript",
            "vc": {
                "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://mm.aueb.gr/contexts/capabilities/v1"
                ],
                "type": ["VerifiableCredential","CapabilitiesCredential"],
                "credentialSubject": {
                    "capabilities": {
                        "https://zero.cloud": ["FL_READ", "FL_WRITE"]
                    }
                }
            }
        }
        vc = jwt.JWT(header=jwt_header, claims=jwt_claims)
        vc.make_signed_token( self.key)
        return vc.serialize()
    
    def issue_without_FL_WRITE(self):
        jwt_header = {
            "typ": "jwt",
            "alg": "ES256",
            "jwk":  self.key.export_public(as_dict=True)
        }
        jwt_claims = {
            "iss": "http://testscript",
            "aud": "https://zero.cloud",
            "vc": {
                "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://mm.aueb.gr/contexts/capabilities/v1"
                ],
                "type": ["VerifiableCredential","CapabilitiesCredential"],
                "credentialSubject": {
                    "capabilities": {
                        "https://zero.cloud": ["FL_READ"]
                    }
                }
            }
        }
        vc = jwt.JWT(header=jwt_header, claims=jwt_claims)
        vc.make_signed_token( self.key)
        return vc.serialize()

    def issue_valid_did_key_iss(self):
        '''
        For this we need Ed25519 keys
        >>> key = jwk.JWK.generate(kty='OKP', crv='Ed25519')
        >>> print (key.export(as_dict=True))
        '''
        key_dict = {'kty': 'OKP', 'crv': 'Ed25519', 'x': 'zEv68b3ZZ6FPV5CsuhZHYNNt-AKF0f11DZSHvNDPSoo', 'd': 'N8ywxRI_wgQuXDyabuW0HQUu4UdnLWqPKuTI40LJabg'}
        key = jwk.JWK.from_json(json.dumps(key_dict))

        jwt_header = {
            "typ": "jwt",
            "alg": "EdDSA",
            "jwk":  key.export_public(as_dict=True)
        }
        
        jwt_claims = {
            "iss": "did:key:z" + base58.b58encode( b'\xed\x01'+base64url_decode(key_dict['x'])).decode(),
            "aud": "https://zero.cloud",
            "vc": {
                "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://mm.aueb.gr/contexts/capabilities/v1"
                ],
                "type": ["VerifiableCredential","CapabilitiesCredential"],
                "credentialSubject": {
                    "capabilities": {
                        "https://zero.cloud": ["FL_READ", "FL_WRITE"]
                    }
                }
            }
        }
        vc = jwt.JWT(header=jwt_header, claims=jwt_claims)
        vc.make_signed_token(key)
        return vc.serialize()

    def issue_revoked_vc(self):
        jwt_header = {
            "typ": "jwt",
            "alg": "ES256",
            "jwk":  self.key.export_public(as_dict=True)
        }
        jwt_claims = {
            "iss": "http://testscript",
            "aud": "https://zero.cloud",
            "vc": {
                "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://mm.aueb.gr/contexts/capabilities/v1",
                "https://w3id.org/vc/status-list/v1"
                ],
                "type": ["VerifiableCredential","CapabilitiesCredential"],
                "credentialSubject": {
                    "capabilities": {
                        "https://zero.cloud": ["FL_READ", "FL_WRITE"]
                    }
                },
                "credentialStatus":{
                    "type": "RevocationList2021Status",
                    "statusListIndex": "9",
                    "statusListCredential": "https://issuer.mmlab.edu.gr/credential/teststatus"
                }
            }
        }
        vc = jwt.JWT(header=jwt_header, claims=jwt_claims)
        vc.make_signed_token( self.key)
        return vc.serialize()

    def issue_non_revoked_vc(self):
        jwt_header = {
            "typ": "jwt",
            "alg": "ES256",
            "jwk":  self.key.export_public(as_dict=True)
        }
        jwt_claims = {
            "iss": "http://testscript",
            "aud": "https://zero.cloud",
            "vc": {
                "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://mm.aueb.gr/contexts/capabilities/v1",
                "https://w3id.org/vc/status-list/v1"
                ],
                "type": ["VerifiableCredential","CapabilitiesCredential"],
                "credentialSubject": {
                    "capabilities": {
                        "https://zero.cloud": ["FL_READ", "FL_WRITE"]
                    }
                },
                "credentialStatus":{
                    "type": "RevocationList2021Status",
                    "statusListIndex": "10",
                    "statusListCredential": "https://issuer.mmlab.edu.gr/credential/teststatus"
                }
            }
        }
        vc = jwt.JWT(header=jwt_header, claims=jwt_claims)
        vc.make_signed_token( self.key)
        return vc.serialize()
          

if __name__ == '__main__':
    issuer = Issuer()
    print (issuer.issue_valid_vc())

