#!/bin/bash
# Script to verify the WASM file hash
# Can be used in CI/CD pipelines to ensure the WASM file matches the expected hash

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
WASM_DIR="$PROJECT_ROOT/src/wasm"
WASM_FILE="$WASM_DIR/didkit_compiled.wasm"
HASH_FILE="$WASM_DIR/didkit_wasm.sha256"

echo "=== Verifying WASM Hash ==="

# Check if files exist
if [ ! -f "$WASM_FILE" ]; then
    echo "❌ Error: WASM file not found: $WASM_FILE"
    echo "    Run ./scripts/build_didkit_c_api.sh to build it first"
    exit 1
fi

if [ ! -f "$HASH_FILE" ]; then
    echo "❌ Error: Hash file not found: $HASH_FILE"
    echo "    Run ./scripts/build_didkit_c_api.sh to generate it"
    exit 1
fi

# Read the expected hash
EXPECTED_HASH=$(cat "$HASH_FILE" | awk '{print $1}')
echo "Expected hash: $EXPECTED_HASH"

# Calculate the actual hash
if command -v sha256sum &> /dev/null; then
    ACTUAL_HASH=$(sha256sum "$WASM_FILE" | awk '{print $1}')
elif command -v shasum &> /dev/null; then
    ACTUAL_HASH=$(shasum -a 256 "$WASM_FILE" | awk '{print $1}')
else
    echo "❌ Error: Neither sha256sum nor shasum is installed"
    exit 1
fi

echo "Actual hash:   $ACTUAL_HASH"

# Compare hashes
if [ "$EXPECTED_HASH" = "$ACTUAL_HASH" ]; then
    echo "✅ WASM hash verification successful!"
    
    # Output for CI/CD
    echo "VELA_WASM_HASH=$ACTUAL_HASH" > "$WASM_DIR/wasm_hash.env"
    echo "Hash saved to $WASM_DIR/wasm_hash.env for CI/CD integration"
    
    # Set environment variable for GitHub Actions if running in that context
    if [ -n "$GITHUB_ENV" ]; then
        echo "VELA_WASM_HASH=$ACTUAL_HASH" >> $GITHUB_ENV
        echo "Set VELA_WASM_HASH environment variable for GitHub Actions"
    fi
    
    exit 0
else
    echo "❌ WASM hash verification failed!"
    echo "The WASM file may have been modified or corrupted"
    exit 1
fi 