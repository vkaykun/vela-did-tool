# WASM Integration for Vela DID Tool

This directory contains the WASM-related components of the Vela DID Tool, including the DIDKit WASM binary and interfaces for it.

## Production Safety Mechanisms

The Vela DID Tool implements multiple layers of protection against the use of mock cryptographic implementations in production:

### 1. Runtime Production Guard

The `production_guard.py` module enforces that mock implementations cannot be used when the system is running in production mode. Production mode is activated by setting the environment variable:

```
VELA_PRODUCTION_MODE=true
```

When running in production mode:
- All calls to use mock implementations will raise a `ProductionGuardError`
- Self-tests verify the integrity of the WASM binary
- The system will fail immediately rather than falling back to insecure implementations

### 2. Build-time Exclusion

For maximum security, the production build process physically excludes mock implementations from the final artifact:

- The `build_for_production.py` script removes all mock files during packaging
- The Poetry `build_production` command creates a verified build without mocks
- The production build hardcodes `PRODUCTION_MODE=True` in the shipped code

### Mock Implementation

The `mock_didkit.py` module provides test implementations of the DIDKit APIs for development and testing purposes. This file:

- Must NEVER be used in production environments
- Is automatically excluded from production builds
- Will be blocked from execution by the production guard even if accidentally included

## Development Workflow

When developing the Vela DID Tool:

1. For local development and testing, you can use the mock implementation
2. Write tests that explicitly test both the mock and WASM implementations
3. For production deployment, always use the `build_production` command:
   ```
   poetry run build_production
   ```

## Security Considerations

The integrity of cryptographic operations is critical to the security of the Vela DID Tool. Never attempt to bypass the production guard mechanisms. If you encounter issues with WASM operation in production:

1. DO NOT disable the production guard
2. DO NOT manually include mock implementations
3. Fix the underlying issue with the WASM integration

Report any security concerns immediately via the appropriate channels.

## Expected files:
- `didkit_compiled.wasm`: The main WASM file compiled from didkit

## How to build:

Run the build script from the project root:
```bash
./scripts/build_wasm.sh
```

## Development without WASM:

For development without the actual WASM file, the code includes fallbacks and mocks in the tests.
When running in production, make sure to build the actual WASM file. 