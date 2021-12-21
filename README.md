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

- **type**: It can be `jwt-vc` or `jwt-vc-dpop`
- **filters**: A list of json-path queries
- **trusted_issuers**: A list of objects that map issuer ids (i.e., the `iss` claim) to the following:
  - **issuer_key_type**: The format of the issuer public key, it can be `jw` or `pem_file`
  - **issuer_key**: if issuer_key_type is jwk then this is the jwk, if issuer_key_type is pem_file the this is the path to the pem file



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

