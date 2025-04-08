# Vela DID Tool Tests

This directory contains unit tests for the Vela DID Tool module.

## Running Tests

You can run the tests using pytest:

```bash
# Run all tests
pytest

# Run tests with coverage reporting
pytest --cov=vela_did_tool

# Generate HTML coverage report
pytest --cov=vela_did_tool --cov-report=html
```

## Test Structure

- `test_did_utils.py`: Tests for DID key generation, parsing, and retrieval
- `test_vc_utils.py`: Tests for Verifiable Credential signing and verification (JSON-LD and JWT)
- `test_run.py`: Tests for the main execution flow and error handling

## Mocking Strategy

The tests use mocking to avoid external dependencies:

- PyLD normalization is mocked to provide deterministic results
- Environment variables are mocked for key retrieval tests
- stdin/stdout are mocked to test the command line interface

## Test Coverage

These tests cover:

1. DID key generation and parsing
   - `did_utils.generate_did_key_ed25519()`: Produces valid DIDs and JWKs
   - `did_utils.get_public_key_bytes_from_did()`: Correctly parses valid DIDs and rejects invalid ones
   - `did_utils.get_private_jwk_from_env()`: Retrieves keys with correct/incorrect environment variable names

2. Verifiable Credential operations
   - `vc_utils.sign_credential_jsonld()` and `vc_utils.verify_credential_jsonld()`: Full sign-and-verify round trip
   - `vc_utils.sign_credential_jwt()` and `vc_utils.verify_credential_jwt()`: JWT signing and verification

3. Main module execution
   - Input parsing and validation
   - Dispatch to correct handler functions
   - Error handling
   - Environment variable fallback for parameter retrieval 