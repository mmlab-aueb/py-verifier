# py-verifier
## Usage

### Prerequisites
IAA component is built using Python3. It depends on the following packages:

```bash
python3 -m pip install Werkzeug
python3 -m pip install jsonpath-ng
```

Depending on the type of access tokens that will be used the following additional dependencies are required

#### JWT

```bash
python3 -m pip install jwcrypto
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

