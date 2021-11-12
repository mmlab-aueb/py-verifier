# VC verifier
This a VC verifier implemented by the [ZeroTrustVC](https://mm.aueb.gr/projects/zerotrustvc) project. 
The verifier can be used as an HTTP proxy that transparently protects HTTP-based resources.

The VC verifier is based on the [IAA component of the H2020 SOFIE project](https://github.com/SOFIE-project/identity-authentication-authorization).

## Usage

### Prerequisites
The VC verifier component is built using Python3. It depends on the following packages:

```bash
python3 -m pip install Werkzeug
python3 -m pip install jsonpath-ng
python3 -m pip install jwcrypto
```

### Configuration
The core configuration file of the component is `conf/iaa.conf`. There the protected resources are described. 
The file contains a mapping from resource relative URIs to authentication and proxy configurations.
The authentication entry of a resource contains the following fields:

| Field | Possible values |
| --- | --- |
| type | "jwt-vc", "jwt-vc-dpop" |
| tokens_expire | true, false (optional, used only with type "jwt") |
| issuer_key | The public key of the issuer (see issuer_key_type for accepted key types) |
| issuer_key_file | A path to the key used for signing a JWT (it cannot be used together with issuer_key)|
| issuer_key_type | "jwk", "pem" |
| filters | A list of json-path queries |

## Testing

### Prerequisites
Tests are executed using pytest and pytest-asyncio. To install it execute: 

```bash
python3 -m pip install  pytest 
python3 -m pip install pytest-asyncio
python3 -m pip install requests
```

### Running the tests
From the root directory run `python3 -m pytest -s  tests/` For shorter output alternatively you can run `python3 -m pytest tests/ -s --tb=short`

