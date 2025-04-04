#!/bin/bash
# Script to build DIDKit C-API to WASM for vela-did-tool
# This script builds didkit with C-style exports needed for the WASM interface

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
WASM_DIR="$PROJECT_ROOT/src/wasm"
TMP_DIR="/tmp/didkit_c_api_build"

# Use specific git tags for reproducible builds
DIDKIT_GIT_REF="v0.7.0"
SSI_GIT_REF="v0.7.0"
DIDKIT_REPO="https://github.com/spruceid/didkit.git"
SSI_REPO="https://github.com/spruceid/ssi.git"

echo "=== Building DIDKit C-API to WASM ==="
echo "Project root: $PROJECT_ROOT"
echo "WASM directory: $WASM_DIR"
echo "Using didkit version: $DIDKIT_GIT_REF"
echo "Using ssi version: $SSI_GIT_REF"

# Check for required tools
if ! command -v git &> /dev/null; then
    echo "git is not installed. Please install it first."
    exit 1
fi

if ! command -v cargo &> /dev/null; then
    echo "cargo is not installed. Please install Rust and Cargo first:"
    echo "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    exit 1
fi

if ! command -v sha256sum &> /dev/null && ! command -v shasum &> /dev/null; then
    echo "Neither sha256sum nor shasum is installed. Please install one of them."
    exit 1
fi

# Clean up and create temp directory
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"
cd "$TMP_DIR"

echo "Cloning repositories..."

# Clone SSI
git clone $SSI_REPO
cd ssi
git checkout $SSI_GIT_REF
SSI_COMMIT=$(git rev-parse HEAD)
echo "SSI commit: $SSI_COMMIT"
cd ..

# Clone DIDKit
git clone $DIDKIT_REPO
cd didkit
git checkout $DIDKIT_GIT_REF
DIDKIT_COMMIT=$(git rev-parse HEAD)
echo "DIDKit commit: $DIDKIT_COMMIT"

# Record build info
mkdir -p "$WASM_DIR"
cat > "$WASM_DIR/build_info.txt" << EOF
=== Build Info ===
DIDKit version: $DIDKIT_GIT_REF (commit: $DIDKIT_COMMIT)
SSI version: $SSI_GIT_REF (commit: $SSI_COMMIT)
Build date: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Rust version: $(rustc --version)
EOF

# Ensure we have the wasm32 target installed
if ! rustup target list --installed | grep -q "wasm32-unknown-unknown"; then
    echo "Adding wasm32-unknown-unknown target..."
    rustup target add wasm32-unknown-unknown
fi

# Build the lib/c directory - this contains the C API
cd lib/c

echo "Building DIDKit C-API with WASM target..."

# Use the original Cargo.toml but modify it for our needs
if [ -f "Cargo.toml.orig" ]; then
    cp Cargo.toml.orig Cargo.toml
else
    cp Cargo.toml Cargo.toml.orig
fi

# Update Cargo.toml to explicitly include required crate-type
sed -i.bak 's/crate-type = \["cdylib", "staticlib"\]/crate-type = \["cdylib"\]/' Cargo.toml || echo "Failed to modify crate-type, proceeding anyway"

# Set compile flags for reproducible builds
export RUSTFLAGS="-C target-feature=+atomics,+bulk-memory,+mutable-globals -C link-arg=--no-entry -C link-arg=--export-dynamic"
export CARGO_PROFILE_RELEASE_DEBUG=false
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
export CARGO_PROFILE_RELEASE_LTO=true
export CARGO_PROFILE_RELEASE_OPT_LEVEL=3
export CARGO_PROFILE_RELEASE_PANIC="abort"

# Build with required features
echo "Building with required features: generate, issue, verify..."
cargo build --release --target wasm32-unknown-unknown --features="generate,issue,verify"

WASM_FILE="target/wasm32-unknown-unknown/release/didkit.wasm"

if [ ! -f "$WASM_FILE" ]; then
    echo "❌ Error: WASM build failed, checking parent directory..."
    # Sometimes the WASM file might be in the parent lib directory
    cd ..
    WASM_FILE="target/wasm32-unknown-unknown/release/didkit.wasm"
    if [ ! -f "$WASM_FILE" ]; then
        echo "❌ Error: No WASM file found in parent directory either"
        exit 1
    fi
    echo "Found WASM file in parent directory"
fi

echo "✅ WASM file found"
echo "WASM file: $WASM_FILE"

# Copy the WASM file
echo "Copying $WASM_FILE to $WASM_DIR/didkit_compiled.wasm"
cp "$WASM_FILE" "$WASM_DIR/didkit_compiled.wasm"

# Create a symbolic link to the standard name
echo "Creating symbolic link to $WASM_DIR/didkit.wasm"
ln -sf "$WASM_DIR/didkit_compiled.wasm" "$WASM_DIR/didkit.wasm"

# Generate hash file
cd "$WASM_DIR"
if command -v sha256sum &> /dev/null; then
    sha256sum didkit_compiled.wasm > didkit_wasm.sha256
    WASM_HASH=$(awk '{print $1}' didkit_wasm.sha256)
elif command -v shasum &> /dev/null; then
    shasum -a 256 didkit_compiled.wasm > didkit_wasm.sha256
    WASM_HASH=$(awk '{print $1}' didkit_wasm.sha256)
fi

echo "=== Build Completed ==="
echo "WASM file: $WASM_DIR/didkit_compiled.wasm"
echo "Symbolic link: $WASM_DIR/didkit.wasm"
echo "Hash file: $WASM_DIR/didkit_wasm.sha256"
echo "WASM SHA-256: $WASM_HASH"
echo ""
echo "To verify expected C-API exports, run wasm-tools if available:"
echo "wasm-tools print $WASM_DIR/didkit_compiled.wasm | grep 'export func'"
echo ""
echo "Expected C-API exports include:"
echo "  - didkit_vc_generate_ed25519_key"
echo "  - didkit_key_to_did"
echo "  - didkit_key_to_verification_method"
echo "  - didkit_vc_issue_credential"
echo "  - didkit_vc_verify_credential"
echo "  - didkit_free_string"
echo "  - didkit_error_message"
echo ""
echo "In CI/CD, set VELA_WASM_HASH=$WASM_HASH for runtime verification"

# Set environment variable for GitHub Actions if running in that context
if [ -n "$GITHUB_ENV" ]; then
    echo "VELA_WASM_HASH=$WASM_HASH" >> $GITHUB_ENV
    echo "Set VELA_WASM_HASH environment variable for GitHub Actions"
fi 