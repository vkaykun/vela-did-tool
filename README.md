# Vela DID Tool

A Naptha tool module for decentralized identity management and Verifiable Credential operations, provding foundational trust primtiives for Vela Network and the broader Naptha ecosystem. It currently implements the did:key method using Ed25519 keys and supports JSON-LD/JWT credential formats.

**Status:** Core functions (`generate`, `resolve`, `sign`, `verify`) tested end-to-end on Naptha, including signing via `deploy-secrets`.

## Core Functions

-   `generate`: Creates `did:key:ed25519` & JWK pair.
-   `resolve`: Resolves `did:key` to DID Document.
-   `sign`: Signs VC payload (JSON-LD/JWT) using key from Naptha secret (`agent_did` parameter).
-   `verify`: Verifies signed VC (JSON-LD/JWT).

## Naptha Integration

**Run Command:**
```bash
naptha run tool:vela_did_tool -p '{"func_name": "<function>", "func_input_data": {...params}}'
```

**Key Parameters (`func_input_data`):**
-   `generate`: `{}`
-   `resolve`: `{"did": "did:key:..."}`
-   `sign`: `{"credential": {...}, "agent_did": "did:key:...", "format": "jsonld"|"jwt"}`
-   `verify`: `{"credential": {...}|"jwt_string", "format": "jsonld"|"jwt"}`

**Signing Workflow:**
1.  Use `generate` to get DID & private JWK.
2.  Manually use `naptha deploy-secrets` to store the private JWK. Secret name must be `NAPTHA_SECRET_did_key_{public_key_multibase}`.
3.  Call `sign` function with `agent_did` parameter matching the deployed secret.

**Important Notes:**
*   **Requires Pre-provisioned Keys:** Current workflow needs keys generated and deployed *before* agent signing via `deploy-secrets`. Autonomous agent key bootstrapping is not handled.
*   **Relies on Naptha Secrets:** Security depends on Naptha's `deploy-secrets` implementation (acknowledged by Naptha as under improvement).

## Local Development

```bash
git clone https://github.com/vkaykun/vela-did-tool.git
cd vela-did-tool
poetry install
poetry run pytest # Unit tests
# poetry run python -m vela_did_tool.run --help # Standalone CLI for debug
```

**Dependencies:** `cryptography`, `jwcrypto`, `PyLD==2.0.3`, `py-multibase`, `py-multicodec`, `pydantic`, `naptha-sdk`.

**License:** Apache-2.0
