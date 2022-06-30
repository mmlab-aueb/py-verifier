# VC verifier
## About
A VC verifier that acts as an HTTP proxy

## Research
* The VC verifier is based on the [IAA component of the H2020 SOFIE project](https://github.com/SOFIE-project/identity-authentication-authorization),
it  was created by the [ZeroTrustVC](https://mm.aueb.gr/projects/zerotrustvc) project and it is used by the [SelectShare](https://mm.aueb.gr/projects/selectshare) project.
* The following publications are based on VC Issuer
   * N. Fotiou, E. Faltaka, V. Kalos, A. Kefala, I. Pittaras, V. A. Siris, G. C. Polyzos, "Continuous authorization over HTTP using Verifiable Credentials and OAuth 2.0", in Open Identity Summit 2022 (OID2022), 2022
   * N. Fotiou, V. A. Siris, G. C. Polyzos, Y. Kortesniemi, D. Lagutin, "Capabilities-based access control for IoT devices using Verifiable Credentials", in IEEE Symposium on Security and Privacy Workshops, Workshop on the Internet of Safe Things (SafeThings), 2022  
   * N. Fotiou, V.A. Siris, G.C. Polyzos, "Capability-based access control for multi-tenant systems using Oauth 2.0 and Verifiable Credentials," Proc. 30th International Conference on Computer Communications and Networks (ICCCN), Athens, Greece, July 2021

## Features
*	It acts as a transparent HTTP Proxy 
*	It supports JWT-encoded VCs
*	It supports VC filtering rules using [JSONPath](https://goessner.net/articles/JsonPath/)
*	It supports VC proof-of-possession using [DPoP](https://oauth.net/2/dpop/)
*	It integrates [DID Universal Resolver](https://dev.uniresolver.io/) for supporting the did:web DID method
*	It supports selective disclosure of the forwarded items using [ZKPs](https://identity.foundation/bbs-signature/draft-bbs-signatures.html) (ZKP branch)


## Usage

### Prerequisites
The VC verifier component is built using Python3. It depends on the following packages:

```bash
python3 -m pip install Werkzeug
python3 -m pip install jsonpath-ng
python3 -m pip install jwcrypto
python3 -m pip install base58
```

### Configuration
The core configuration file of the component is `conf/iaa.conf`. There the protected resources are described. 
The file contains a mapping from resource relative URIs to authentication and proxy configurations.
The authentication entry of a resource contains the following fields:

- **type**: It can be `jwt-vc` or `jwt-vc-dpop`. In the former case a VC is used as a
Bearer Token, whereas in the second case a DPoP proof of possession must be provided.
- **filters**: A list of json-path queries for validating the provided VCs. 
- **trusted_issuers**: A list of objects that map issuer ids (i.e., the `iss` claim) to the following:
  - **issuer_key_type**: The format of the issuer public key, it can be `jw` or `pem_file`
  - **issuer_key**: if issuer_key_type is jwk then this is the jwk, if issuer_key_type is pem_file the this is the path to the pem file

A guideline for constructing json-path queries can be found [here](https://support.smartbear.com/alertsite/docs/monitors/api/endpoint/jsonpath.html).
Filters in VC verifier can refer to variables included in the query string of the
URL using the `#` symbol. For example the following filter

```
["$.vc.credentialSubject.capabilities.#deviceID[*]", "#field"]
```

When invoked with a URL like

```
http://localhost:9000/secure/jwt-vc-filter-3?deviceID=device1&field=I1
```

Will become

```
["$.vc.credentialSubject.capabilities.device1[*]", "I1"]
```

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

