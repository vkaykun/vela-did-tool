# Vela DID Tool (`tool:vela-did-tool`)

**Status:** Phase 1 Development (Foundational Identity & Anchoring)

A Naptha Tool Module providing W3C DID (`did:key`) and Verifiable Credential signing/verification operations using the [didkit](https://github.com/spruceid/didkit) Python package. Designed for Vela Network agents and potentially other Naptha users needing authenticated off-chain actions.

---

## Core Features

- Generate `did:key` identifiers with Ed25519 keypairs.
- Sign JSON payloads (including composite messages) into W3C Verifiable Credentials (JWS format via `didkit`).
- Verify signed Verifiable Credentials using `didkit`.
- Status check and self-test operations.

---

## Prerequisites

- Python >= 3.10, <= 3.13
- Poetry
- Naptha SDK (for `naptha` CLI)
- **Native `didkit` library installed:** Crucial for functionality. See [didkit installation guide](https://github.com/spruceid/didkit#installation).

---

## Installation (Native `didkit` Library)

You must install the native `didkit` library in the environment where this tool runs (locally for testing or in your Naptha Node).

## Intended Naptha Deployment & Usage

`vela-did-tool` is designed to run as a standard Naptha Tool Module.

### Registering the Tool (Future Example)

```bash
naptha tools vela-did-tool -p \
  "description='Vela DID tool' module_url='<Public_URL>' module_entrypoint='src/main.py'"
```

> For now, register it with a private Git URL on a local Naptha Node for development.

---

### Running the Tool

Use `naptha run` with parameters passed as JSON via the `-p` flag. Keys are in **kebab-case**.

#### Generate a key

```bash
naptha run tool:vela-did-tool -p '{"operation": "generate"}'
```

#### Sign a message

```bash
naptha run tool:vela-did-tool -p '{"operation": "sign", "agent-did": "did:key:z...", "message": "DataToSign"}'
```

#### Verify a credential

```bash
naptha run tool:vela-did-tool -p '{"operation": "verify", "signed-credential": "<VC_JSON_String>"}'
```

---

## Secrets Management (Private Keys)

### Generate & Deploy

Use the `generate` operation to create a JWK. You must deploy this using `naptha deploy-secrets`.

**Secret name format:**

```
vela_agent_private_key_{DID_with_underscores}
```

```bash
# Example:
# Secret Name: vela_agent_private_key_did_key_z...
# Secret Value: {"kty":"OKP", ...}
```

### Retrieval in Operations

The `sign` and `sign_composite` operations will automatically retrieve the corresponding key using:

```
NAPTHA_SECRET_{secret_name}
```

This is injected by the Naptha Node based on the `agent-did`.

> **Security Note:** Current design relies on Naptha Node’s environment isolation. A hardened secret mechanism is planned.

---

## Development

### Install

```bash
poetry install
```

### Run Tests

```bash
poetry run pytest
```

> Note: Requires native `didkit` installed locally for tests to pass.

---

## License

MIT License

