# Vela DID Tool

A Naptha tool module enabling decentralized identity management (did:key Ed25519) and Verifiable Credential operations (JSON-LD/JWT signing & verification), providing essential trust primitives for applications within the Vela Network and the broader Naptha ecosystem.

## Core Functions

- `generate-did`: Creates a new did:key and JWK pair.
- `resolve-did`: Resolves a did:key to its DID Document.
- `sign`: Signs a credential (JSON-LD or JWT) using a key from Naptha secrets.
- `verify`: Verifies a signed credential (JSON-LD or JWT).

## Naptha Integration

**Run Command:**
```bash
naptha run tool:vela_did_tool -p '{"func_name": "<function_name>", "func_input_data": {...params}}'
```

**Input Parameters (`-p` JSON):**
- `func_name`: (Required) One of `"generate-did"`, `"resolve-did"`, `"sign"`, `"verify"`.
- `func_input_data`: (Required) A JSON object containing function-specific parameters:
  - `did`: (Optional) DID string (for `resolve-did`).
  - `credential`: (Required for `sign`/`verify`) Credential object (dict for JSON-LD) or JWT string (for JWT verify).
  - `format`: (Optional, defaults vary) `"jsonld"` or `"jwt"`.
  - `agent_did` / `issuer_did`: (Required for `sign`) The DID whose private key (stored as a Naptha secret) should be used for signing.

**Example (Signing):**
```bash
# Assumes secret for 'did:key:zTest...' deployed via 'naptha deploy-secrets'
naptha run tool:vela_did_tool -p '{
    "func_name": "sign",
    "func_input_data": {
        "format": "jsonld",
        "agent_did": "did:key:zTestDidForSigning",
        "credential": {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential"],
            "issuer": "did:key:zTestDidForSigning",
            "credentialSubject": {"id": "did:example:subject123"}
        }
    }
}'
```

## Secret Management (Required for Signing)

1.  **Store Keys:** Use `naptha deploy-secrets -e` with environment variables named `NAPTHA_SECRET_{sanitized_did}` containing the private JWK JSON.
    ```env
    # Example for .env file
    NAPTHA_SECRET_did_key_zTestDidForSigning='{"kty":"OKP", "crv":"Ed25519", ...}'
    ```
2.  **Usage:** The `sign` function uses the `agent_did` or `issuer_did` parameter to find the corresponding `NAPTHA_SECRET_...` environment variable within the Naptha worker.

> **⚠️ Security Note:** As per Naptha, the deploy-secrets method is not fully secure and they are working on a solution.

## Local Development & Testing

```bash
# Setup
git clone https://github.com/vkaykun/vela-did-tool.git
cd vela-did-tool
poetry install

# Run unit tests
poetry run pytest
```

*(A standalone CLI via `python -m vela_did_tool.run --help` exists for basic local debugging if needed.)*

## Dependencies

`cryptography`, `jwcrypto`, `PyLD`, `py-multibase`, `py-multicodec`, `pydantic`.

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.
