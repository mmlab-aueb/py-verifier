# py-verifier
## Usage

### Prerequisites
IAA component is built using Python3. It depends on the following packages:

```bash
pip3 install Werkzeug
pip3 install jsonpath-ng
```

Depending on the type of access tokens that will be used the following additional dependencies are required

#### JWT

```bash
pip3 install jwcrypto
```

## Testing

### Prerequisites
Tests are executed using pytest and pytest-asyncio. To install it execute: 

```bash
pip3 install -U pytest 
pip3 install pytest-asyncio
```

### Running the tests
From the root directory run `python3 -m pytest -s  tests/` For shorter output alternatively you can run `python3 -m pytest tests/ -s --tb=short`

