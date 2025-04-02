# Vela DID Tool (`tool:vela-did-tool`)

**A standards-compliant DID (`did:key`) management and cryptographic signing tool packaged as a Naptha Module for the Vela Network.**

`vela-did-tool` provides essential identity functions for agents within Vela, enabling them to prove authorship of data (like task results) using decentralized identifiers and JSON Web Signatures (JWS). It leverages the robust `didkit` library (Rust compiled to WASM) for core operations.

## Core Features

*   **DID Generation:** Creates `did:key` identifiers (Ed25519/Secp256k1) with JWK key pairs.
*   **Secure Key Storage:** Optionally encrypts (AES-GCM) and stores private JWKs using Naptha's `StorageProvider` (FS or DB backend).
    *   Relies on a runtime-provided secret for decryption. **(See Security Considerations!)**
*   **JWS Signing:** Signs JSON payloads using a specified agent's stored private key.
*   **JWS Verification:** Verifies JWS signatures against a `did:key`.
*   **Naptha Integration:** Packaged as a Tool Module callable via `naptha run tool:vela-did-tool ...`.

## Prerequisites

*   **Naptha Node Environment:**
    *   `vela-did-tool` installed/registered on the Node.
    *   Compatible WebAssembly Runtime (e.g., `wasmtime`) installed.
    *   `StorageProvider` configured (FS or DB backend).
*   **Secret Management:** A secure method to provide the decryption secret via an environment variable to the tool's runtime context when using stored keys.

## Installation (as a Naptha Dependency)

Add `vela-did-tool` to your Naptha module's `pyproject.toml`:

```toml
[tool.poetry.dependencies]
# ... other dependencies
vela-did-tool = { git = "https://github.com/your-org/vela-did-tool.git", rev = "main" } # Or path, version etc.
```

Note: Ensure the vela-did-tool package build correctly includes its necessary WASM binaries.

Configuration

Naptha Node: Ensure the prerequisites (WASM Runtime, StorageProvider) are met on Nodes running this tool.

Key Storage: Keys managed by this tool (when using --store during generation) are stored encrypted under the Node's StorageProvider path, typically following the convention: agent_keys/<agent_id>/private.key.enc.

Secret Provision: When using stored keys (sign command or future retrieval), the decryption secret MUST be provided securely to the tool's runtime environment via the environment variable named by the --secret-env option (defaults to AGENT_SECRET).

⚠️ Critical Security Considerations ⚠️

Secret Management: The default mechanism relies on secrets passed via environment variables. This is INSECURE for production. Environment variables can be exposed through various means. Production deployments MUST integrate with secure secret management systems (e.g., HashiCorp Vault, Cloud KMS/Secret Manager, HSMs) and update the key retrieval logic accordingly.

Naptha Node Trust: Secure key storage relies heavily on the Naptha Node's ability to isolate module environments and storage access. Access control within the StorageProvider implementation is assumed but not specified in core Naptha docs. Treat Nodes running this tool with stored keys as highly sensitive.

Usage (Naptha Tool CLI)

Invoke the tool using the naptha run tool:vela-did-tool command, passing parameters via the -p flag or environment variables. Output is typically JSON to stdout.

1. Generate Key Pair (generate)

```bash
# Generate ephemeral key (private key printed to output - handle securely!)
naptha run tool:vela-did-tool -p "operation=generate key_type=Ed25519"

# Generate and store encrypted key (requires secret in AGENT_SECRET env var)
naptha run tool:vela-did-tool -p "operation=generate key_type=Ed25519 store=true agent_id=agent-007 storage_type=db secret_env=AGENT_SECRET"
```

Outputs: JSON containing did, publicKeyJwk, and privateKeyJwk (only if store=false), plus key_stored status.

2. Sign Payload (sign)

```bash
# Requires key previously stored for 'agent-007'
# Requires secret in AGENT_SECRET env var
naptha run tool:vela-did-tool -p 'operation=sign agent_id=agent-007 secret_env=AGENT_SECRET payload={"resultCID":"Qm...", "codeId":"ipfs://..."} storage_type=db'
```

Required Args: agent_id, payload (valid JSON string), secret_env (env var name).

Outputs: JSON { "jws": "eyJhbG..." } on success, or {"error": "..."} on failure.

3. Verify Signature (verify)

```bash
naptha run tool:vela-did-tool -p 'operation=verify did=did:key:z6Mkt... jws=eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDprZXk6ejZNa3Q...'
```

Required Args: did, jws.

Outputs: JSON { "verified": true } or { "verified": false, "error": "..." }.

(Note: Payloads for signing must be passed as valid JSON strings. Secrets must be present in the tool's execution environment.)

## Technical Overview

Core: Rust library using didkit.

Interface: Compiled to WASM (wasm-pack), loaded via Python (wasmtime).

Naptha Interface: Python wrapper (vela_did_tool_py) and entry script (run.py) using typer or argparse.

Storage Interaction: Uses naptha-sdk's StorageProvider.

Encryption: cryptography library (AES-GCM) using runtime-provided secret.

## Development

(Setup)

```bash
git clone https://github.com/your-org/vela-did-tool.git
cd vela-did-tool
# Build/fetch Rust WASM core (see internal docs/scripts)
poetry install --with dev
```

(Testing)

```bash
poetry run pytest tests/
```

Contributions are welcome. Please see CONTRIBUTING.md.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.1.0-blue)](...) <!-- Placeholder: Link to releases or PyPI -->
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](...) <!-- Placeholder: Link to CI/CD -->
