# Vela DID Tool

A Naptha Tool Module that provides standard DID-based signing and verification for off-chain tasks, particularly for Vela Network Phase 1 but also usable by others. It uses [didkit](https://github.com/spruceid/didkit) (a Rust/WASM library) for cryptographically correct DID generation (did:key + Ed25519 keypairs) and Verifiable Credential signing/verification.

## Features

- Generate `did:key` identifiers with Ed25519 keypairs
- Sign messages using W3C Verifiable Credentials with cryptographic proofs
- Verify signatures with DIDKit's built-in DID resolution
- Support for composite messages (resultPointer + codeId)
- WASM binary integrity verification for enhanced security
- Credential expiration support with configurable expiration dates
- Self-test capability to validate cryptographic operations
- Enhanced security model with external key management

## Prerequisites

- Python 3.10+ (tested on Python 3.10-3.13)
- Rust & cargo (for building WASM from didkit)
- wasm-pack or direct cargo wasm32 target support
- Poetry (for Python dependency management)
- Naptha SDK v1.0.2+
- External secure key management (vela-secure-key-accessor or equivalent)

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/YourOrg/vela-did-tool.git
cd vela-did-tool
```

### 2. Install dependencies

```bash
poetry install
```

### 3. Build didkit to WASM

```bash
./scripts/build_didkit_c_api.sh
```

This script will:
1. Clone the didkit and ssi repositories at specific versions (v0.7.0)
2. Build didkit to WASM with the required features (generate, issue, verify)
3. Place the resulting file in the src/wasm directory 
4. Generate a SHA-256 hash in `didkit_wasm.sha256` for integrity verification
5. Create a symbolic link from `didkit_compiled.wasm` to `didkit.wasm`

The build script is designed to be reproducible, using fixed versions and compiler settings to ensure consistent output.

## Usage

The tool is designed to be used as a Naptha Tool Module. It supports the following operations:

### 1. Generate a new DID

```bash
naptha run tool:vela_did_tool -p "operation='generate'"
```

Sample Output:
```json
{
  "status": "success",
  "did": "did:key:z3T6gKW...",
  "verificationMethod": "did:key:z3T6gKW...#z3T6gKW...",
  "privateKeyJwk": {
    "kty": "OKP", 
    "crv": "Ed25519",
    "d": "...", 
    "x": "..."
  },
  "publicKeyJwk": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "..."
  },
  "message": "Generated DID: did:key:z3T6gKW... IMPORTANT: Store the privateKeyJwk using 'naptha deploy-secrets'."
}
```

**Important:** You must provision the private key with the Naptha Secrets API:

```bash
# Save the privateKeyJwk to a temporary file
echo '{"kty":"OKP","crv":"Ed25519","d":"...","x":"..."}' > /tmp/private_key.json

# Deploy it as a secret (replace DID value with your actual DID)
naptha deploy-secrets --name vela_agent_private_key_did_key_z3T6gKW... --from-file /tmp/private_key.json

# Remove the temporary file
rm /tmp/private_key.json
```

### 2. Sign a message

```bash
# First, retrieve the private key securely using vela-secure-key-accessor (or equivalent)
PRIVATE_KEY=$(naptha run tool:vela-secure-key-accessor -p "operation='retrieve' key_name='agent_key_123'")

# Then sign using the retrieved key
naptha run tool:vela_did_tool -p "operation='sign' agent_did='did:key:z3T6gKW...' message='HelloVela' private_key_jwk='$PRIVATE_KEY' expiration_days=180"
```

Sample Output:
```json
{
  "status": "success",
  "signedCredential": "{\"@context\":[\"https://www.w3.org/2018/credentials/v1\"],\"id\":\"urn:uuid:...\",\"type\":[\"VerifiableCredential\",\"MachineCredential\",\"AgentCredential\"],\"issuer\":\"did:key:z3T6gKW...\",\"issuanceDate\":\"2023-06-01T12:00:00Z\",\"expirationDate\":\"2023-12-01T12:00:00Z\",\"credentialSubject\":{\"id\":\"did:key:z3T6gKW...\",\"message\":\"HelloVela\"},\"proof\":{...}}"
}
```

### 3. Sign a composite message

```bash
# First, retrieve the private key securely
PRIVATE_KEY=$(naptha run tool:vela-secure-key-accessor -p "operation='retrieve' key_name='agent_key_123'")

# Then sign the composite message
naptha run tool:vela_did_tool -p "operation='sign_composite' agent_did='did:key:z3T6gKW...' result_pointer='abc123' code_id='xyz789' subject_did='did:key:z456...' private_key_jwk='$PRIVATE_KEY'"
```

Sample Output:
```json
{
  "status": "success",
  "signedCredential": "{\"@context\":[\"https://www.w3.org/2018/credentials/v1\"],\"id\":\"urn:uuid:...\",\"type\":[\"VerifiableCredential\",\"MachineCredential\",\"AgentCredential\"],\"issuer\":\"did:key:z3T6gKW...\",\"issuanceDate\":\"2023-06-01T12:00:00Z\",\"credentialSubject\":{\"id\":\"did:key:z456...\",\"resultPointer\":\"abc123\",\"codeId\":\"xyz789\"},\"proof\":{...}}"
}
```

### 4. Verify a signed credential

```bash
naptha run tool:vela_did_tool -p "operation='verify' signed_credential='{...}' expected_message='HelloVela' expected_subject='did:key:z456...'"
```

Sample Output:
```json
{
  "status": "success",
  "valid": true,
  "contentValid": true,
  "details": {
    "checks": ["proof"],
    "warnings": [],
    "errors": []
  }
}
```

### 5. Check system status

```bash
naptha run tool:vela_did_tool -p "operation='status'"
```

Sample Output:
```json
{
  "status": "success",
  "productionMode": true,
  "usingMock": false,
  "wasmIntegrity": {
    "checkPerformed": true,
    "fileExists": true,
    "hashVerified": true,
    "expectedHash": "5a3dc...7f42",
    "actualHash": "5a3dc...7f42"
  }
}
```

### 6. Perform self-test

```bash
naptha run tool:vela_did_tool -p "operation='self_test'"
```

Sample Output:
```json
{
  "status": "success",
  "message": "Self-test completed successfully"
}
```

## Production Mode

For production environments, the tool supports a strict mode that prevents usage of the mock implementation:

```bash
export VELA_PRODUCTION_MODE=true
export VELA_WASM_HASH=5a3dc...7f42  # Optional but recommended (SHA-256 hash of wasm file)
naptha run tool:vela_did_tool -p "operation='generate'"
```

When `VELA_PRODUCTION_MODE` is set to `true`:

- The tool will only use the actual didkit WASM implementation
- It will fail with a clear error if the WASM file is missing or cannot be loaded
- WASM file integrity will be verified if `VELA_WASM_HASH` is provided
- No fallback to the mock implementation will be attempted
- A self-test is performed at startup to ensure crypto operations are working correctly
- A security check at startup will prevent the tool from running with mocks in production mode

This ensures cryptographic security in production environments.

### Enhanced Security Features

The tool implements several security features for production use:

1. **WASM Integrity Verification**: When `VELA_WASM_HASH` is set, the tool validates the SHA-256 hash of the WASM file at startup to ensure it hasn't been tampered with.

2. **Cryptographic Self-Test**: In production mode, the tool performs a self-test at startup by generating a test key, issuing a credential, and verifying it. This ensures the cryptographic stack is working correctly.

3. **Strict Error Handling**: In production mode, any cryptographic operation failure is treated as a fatal error, with no fallback to insecure code.

4. **Memory Safety**: The WASM wrapper uses `try/finally` blocks to ensure proper memory management even when exceptions occur.

5. **Export Verification**: The tool verifies that all required WASM exports are present at startup to prevent running with an incomplete or incorrect WASM file.

## Production Safety Features

The vela-did-tool implements strict security controls to ensure that mock implementations are completely unavailable in production environments. These safeguards provide a strong barrier against accidental use of insecure implementations in critical environments.

## Production Mode Guards

The tool enforces several layers of protection:

1. **Runtime Environment Detection**: 
   - The `VELA_PRODUCTION_MODE` environment variable controls the operational mode
   - When set to "true", all mock implementations are disabled
   - In production, cryptographic operations will fail closed (terminate) rather than falling back to insecure mocks

2. **Build-time Controls**:
   - Use `poetry run build_production` to create a production-only build
   - This command physically excludes all mock implementations from the package
   - The build process hardcodes `PRODUCTION_MODE=True` in the shipped code
   - The verification step confirms no mock files are present in the final artifact

3. **Import Guards**:
   - Any attempt to import mock modules in production will immediately raise a critical error and terminate
   - Runtime checks prevent mock code from executing, even if accidentally included

4. **WASM Integrity Verification**:
   - The WASM binary's integrity is verified via cryptographic hash
   - In production, a hash mismatch will abort the process rather than continuing with a potentially tampered binary
   - The expected hash is hardcoded or provided via a secure configuration channel

5. **Self-tests at Startup**:
   - In production mode, a self-test verifies that all cryptographic operations are functioning correctly
   - The self-test creates a temporary key, signs a credential, and verifies it
   - Any failure during self-test causes immediate termination

## Creating Production Builds

To create a secure production build that physically excludes mock implementations:

```bash
# Create a production build with verification
poetry run build_production --verify

# Clean existing artifacts first
poetry run build_production --clean --verify

# Specify output directory
poetry run build_production --output-dir secure_dist --verify
```

The production build script:
1. Creates a clean copy of the codebase
2. Physically removes all mock implementations
3. Hardens the production guard to always be enabled
4. Builds the distribution package
5. Verifies the final artifact contains no mock files

This approach provides physical assurance that mock implementations cannot be used in production, even if runtime checks fail.

## Testing Production Guards

A dedicated test script at `scripts/test_production_mode.py` verifies these safety mechanisms:

```bash
# Run the tests
./scripts/test_production_mode.py
```

## Development vs Production

For development and testing, mock implementations can be used by setting:

```bash
export VELA_PRODUCTION_MODE=false
```

For production deployment, use both runtime protection and build-time protection:

```bash
# Runtime protection
export VELA_PRODUCTION_MODE=true

# Build-time protection (when creating distributable package)
poetry run build_production --verify
```

The build-time protection physically excludes mock implementations from the distribution package, providing the strongest possible assurance that mocks cannot be used in production.

For CI/CD pipelines, integrate the verification step to ensure only verified production builds are deployed:

```bash
# In CI/CD pipeline
poetry run build_production --verify --clean
# If the above command succeeds (exit code 0), the build is certified mock-free
```

## Known Limitations

- The WASM hash verification relies on the actual hash being correct in the code - update this when upgrading DIDKit versions
- Some environment detection is only performed at startup - changing environment variables at runtime may not be detected
- Development packages include mock implementations for testing - always use the `build_production` command for production deployments to physically exclude mock code from the package

## Development

### Running Tests

```bash
poetry run pytest
```

### Local Development Without WASM

During development, the tool can operate without the actual WASM file using a mock implementation. This is **NOT SECURE** and is only intended for development and testing purposes.

If the WASM file is not available and `VELA_PRODUCTION_MODE` is not set to `true`, the tool will automatically use a mock implementation that mimics the behavior but does not provide actual cryptographic operations.

You'll see warning logs whenever the mock implementation is used.

### WASM Integration

The tool integrates with didkit's WASM module using its C-style FFI interface:

1. **Building Didkit**: We prefer direct cargo build with `cargo build --target wasm32-unknown-unknown --features="generate,verify,issue"` to get C-style exports, with fallback to wasm-pack
2. **Function Names**: The WASM module exports C-style function names like `didkit_vc_generate_ed25519_key` and `didkit_key_to_did`
3. **Memory Management**: We use `didkit_free_string` to properly free allocated strings
4. **DID Generation Process**:
   - First call `didkit_vc_generate_ed25519_key()` to create an Ed25519 key pair
   - Then call `didkit_key_to_did("key", keyJson)` to convert the key to a did:key identifier
   - Also get the verification method with `didkit_key_to_verification_method`
5. **Signing & Verification**: Uses Verifiable Credential format with `didkit_vc_issue_credential` and `didkit_vc_verify_credential`

To verify the WASM exports, install `wasm-tools` and run:
```bash
wasm-tools print src/wasm/didkit_compiled.wasm | grep "export func"
```

This will show you the available exports like `didkit_vc_generate_ed25519_key`, `didkit_key_to_did`, etc.

### Verifiable Credential Format

The tool uses enhanced W3C Verifiable Credentials to securely package messages:

```json
{
  "@context": ["https://www.w3.org/2018/credentials/v1"],
  "id": "urn:uuid:123e4567-e89b-12d3-a456-426614174000",
  "type": ["VerifiableCredential", "MachineCredential", "AgentCredential"],
  "issuer": "did:key:z3T6gKW...",
  "issuanceDate": "2023-06-01T12:00:00Z",
  "expirationDate": "2023-12-01T12:00:00Z",
  "credentialSubject": {
    "id": "did:key:z3T6gKW...",
    "message": "HelloVela"
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2023-06-01T12:00:00Z",
    "verificationMethod": "did:key:z3T6gKW...#z3T6gKW...",
    "proofPurpose": "assertionMethod",
    "proofValue": "..."
  }
}
```

For composite messages, both values are included in the `credentialSubject`:

```json
"credentialSubject": {
  "id": "did:key:z3T6gKW...",
  "resultPointer": "abc123",
  "codeId": "xyz789"
}
```

Enhancements over basic VC format:
- Added a unique credential `id` using UUID
- Added explicit `credentialSubject.id` to clearly identify the subject
- Included custom types `MachineCredential` and `AgentCredential`
- Added optional `expirationDate` to support credential rotation
- Used W3C standard-compliant fields for better interoperability

### Publishing to Naptha

To publish the tool to a Naptha node:

```bash
naptha tools create tool:vela_did_tool -p \
  "description='Vela DID-based signing tool' \
   module_url='https://github.com/YourOrg/vela-did-tool' \
   module_entrypoint='src/main.py'"
```

## Architecture

The project follows a modular architecture:

1. `main.py`: Naptha tool entrypoint that processes operations and input parameters
2. `did_utils.py`: High-level DID operations (generation, signing, verification)
3. `secrets_handler.py`: Integration with Naptha Secrets API (v1.0.2+) for secure key retrieval
4. `wasm_wrapper.py`: Low-level integration with didkit WASM using C-style functions
5. `wasm/mock_didkit.py`: Development-only mock implementation

### Secrets Management

The tool integrates with Naptha Secrets API v1.0.2+ for secure key retrieval. Key management follows this workflow:

1. **Key Generation**: The tool generates a DID and returns the privateKeyJwk to the caller
2. **Key Provisioning**: The caller must deploy the privateKeyJwk using `naptha deploy-secrets` CLI command 
3. **Key Retrieval**: During operations that require signing, the tool retrieves the private key using the SDK's `get_secret` function

Keys are identified by a standard naming convention: `vela_agent_private_key_did_key_z3T6gKW...` (where the DID is formatted with underscores instead of colons).

#### Development Mode Fallback

In development mode only (when `VELA_PRODUCTION_MODE` is not set to `true`), the tool can fall back to using environment variables for secret retrieval if the Naptha Secrets API is unavailable. This allows for easier local testing but is NOT secure for production use.

### Parameter Passing

The tool accepts parameters in several formats, in order of precedence:

1. **Command-line arguments**: Passed directly to the tool's entrypoint (e.g., `--operation generate`)
2. **JSON file**: Specified with `--input-file` argument or `INPUT_FILE` environment variable
3. **Environment variables**: Using `INPUT_OPERATION`, `INPUT_AGENT_DID`, etc. (for development/testing only)

When using the tool with `naptha run tool:vela_did_tool -p "..."`, the parameters are passed using the standardized naming convention (all lowercase with underscores):

```bash
naptha run tool:vela_did_tool -p "operation='sign' agent_did='did:key:z3T6gKW...' message='Hello'"
```

This matches the expected parameter names in the SDK's `ToolRunInput` interface.

## Troubleshooting

### WASM Build Issues

If you encounter issues with the WASM build:

1. Verify you have wasm-pack installed: `wasm-pack --version`
2. Check that you have the wasm32 target installed: `rustup target list --installed`
3. If the wasm32 target is missing: `rustup target add wasm32-unknown-unknown`
4. Examine the WASM exports to ensure they match what the tool expects:
   ```
   wasm-tools print src/wasm/didkit_compiled.wasm | grep "export func"
   ```
5. Make sure the build includes the necessary features: generate, issue, verify

### Parameter Issues

If you encounter issues with parameters not being recognized:

1. Verify parameter naming: Use snake_case format (e.g., `agent_did` not `AGENT_DID`)
2. Check parameter values: Ensure string values are properly quoted in the `-p` string
3. For complex JSON values, use proper JSON string escaping
4. In development mode, try setting environment variables for testing: `export INPUT_OPERATION=generate`
5. You can use `echo` to verify that your parameter string is well-formed:
   ```bash
   echo "operation='sign' agent_did='did:key:z3T6gKW...' message='Hello'"
   ```

### Secrets API Issues

If you encounter issues with private key retrieval:

1. Verify the key is provisioned correctly with `naptha secrets list`
2. Check the secret name matches the expected format: `vela_agent_private_key_did_key_z3T6gKW...`
3. Ensure the Node has the necessary permissions to access secrets
4. Try provisioning the secret again with `naptha deploy-secrets`
5. In production mode, there is no fallback if secret retrieval fails - this is a security feature

### Security Issues

If you encounter security-related issues:

1. Check that you're using production mode: `export VELA_PRODUCTION_MODE=true`
2. Verify WASM integrity with `operation='status'` to see if the hash matches
3. Review logs for any "USING MOCK" warnings - these should never appear in production
4. Run `operation='self_test'` to verify that all cryptographic operations work correctly
5. Make sure the tool is running with sufficient permissions to read the WASM file

## License

[MIT License](LICENSE)

## Contributors

- Vela Team 

## Security Model

The tool uses an enhanced security model where private keys are managed externally:

1. **External Key Management**: Private keys are not stored within the tool itself but are retrieved from a secure key management service (like vela-secure-key-accessor) and passed as parameters.

2. **Per-operation Key Passing**: For each signing operation, the private key must be explicitly retrieved and passed in the `private_key_jwk` parameter.

3. **Separation of Concerns**: This design separates key management from signing operations, allowing different security policies to be implemented around key access.

4. **Integration with Secure Services**: The recommended approach is to use a dedicated key management tool (like vela-secure-key-accessor) that integrates with enterprise-grade key management services such as HashiCorp Vault, AWS KMS, or similar systems.

5. **Ephemeral Key Usage**: Keys are only held in memory for the duration of the signing operation and not persisted by the tool.

The following diagram illustrates the recommended security flow:

```
Orchestrator/Workflow
       |
       |--> vela-secure-key-accessor (retrieves key from Vault/KMS)
       |           |
       |           V
       |     [private_key_jwk]
       |           |
       V           V
  vela-did-tool (receives key as parameter,
                uses it to sign, then discards)
```

This flow ensures that:
- Keys are only accessible to authorized services with proper authentication
- Keys are never stored in the vela-did-tool codebase or state
- Each signing operation requires explicit authorization via the secure key accessor
- The tool can be audited separately from key management concerns

### Workflow Integration Example

Here's a sample workflow that demonstrates the secure pattern:

```python
# In a Naptha workflow/orchestrator
async def sign_computation_result(agent_did, result_pointer, code_id):
    # 1. Securely retrieve the private key
    key_accessor_response = await naptha.run_tool(
        "vela-secure-key-accessor",
        {
            "operation": "retrieve",
            "key_name": f"agent_{agent_did.replace(':', '_')}"
        }
    )
    
    if key_accessor_response.get("status") != "success":
        raise Exception("Failed to retrieve key")
    
    private_key_jwk = key_accessor_response.get("key")
    
    # 2. Use the key to sign the result
    sign_response = await naptha.run_tool(
        "vela-did-tool",
        {
            "operation": "sign_composite",
            "agent_did": agent_did,
            "result_pointer": result_pointer,
            "code_id": code_id,
            "private_key_jwk": private_key_jwk
        }
    )
    
    # 3. Return the signed credential
    return sign_response.get("signedCredential")
```

## CI/CD Integration

The vela-did-tool includes CI/CD integration for WASM builds and hash verification:

### GitHub Actions Integration

Add the following to your GitHub workflow file:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
          target: wasm32-unknown-unknown
          override: true
      
      - name: Build DIDKit WASM
        run: ./scripts/build_didkit_c_api.sh
        # This will set VELA_WASM_HASH in the GitHub environment
      
      - name: Upload WASM artifacts
        uses: actions/upload-artifact@v3
        with:
          name: didkit-wasm
          path: |
            src/wasm/didkit_compiled.wasm
            src/wasm/didkit_wasm.sha256
            src/wasm/build_info.txt
```

### GitLab CI Integration

Add the following to your `.gitlab-ci.yml`:

```yaml
build-wasm:
  stage: build
  image: rust:slim-bullseye
  script:
    - rustup target add wasm32-unknown-unknown
    - ./scripts/build_didkit_c_api.sh
    - WASM_HASH=$(cat src/wasm/didkit_wasm.sha256 | awk '{print $1}')
    - echo "VELA_WASM_HASH=$WASM_HASH" >> build.env
  artifacts:
    paths:
      - src/wasm/didkit_compiled.wasm
      - src/wasm/didkit_wasm.sha256
      - src/wasm/build_info.txt
    reports:
      dotenv: build.env
```

### Setting VELA_WASM_HASH in Production

For production deployments, set the `VELA_WASM_HASH` environment variable using the hash from the build:

```bash
# Get the hash from the build output
WASM_HASH=$(cat src/wasm/didkit_wasm.sha256 | awk '{print $1}')

# Set it in your deployment environment
export VELA_WASM_HASH=$WASM_HASH
```

Alternatively, you can add the hash to your application configuration or as an environment variable in your container definition.

### Verifying WASM Integrity

The tool will automatically verify the WASM file integrity at startup when `VELA_WASM_HASH` is set:

```bash
export VELA_PRODUCTION_MODE=true
export VELA_WASM_HASH=5a3dc...7f42  # Use the actual hash from didkit_wasm.sha256
naptha run tool:vela_did_tool -p "operation='status'"
```

This will show the hash verification status in the response. 