#!/bin/bash
# Convenient script for running the vela-did-tool

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

# Check if Naptha CLI is available
if command -v naptha &> /dev/null; then
    HAS_NAPTHA=true
else
    HAS_NAPTHA=false
fi

# Function to print usage
print_usage() {
    echo "Usage: ./scripts/run_tool.sh OPERATION [OPTIONS]"
    echo ""
    echo "Operations:"
    echo "  generate                Generate a new DID and store the private key"
    echo "  sign DID MESSAGE        Sign a message with the given DID"
    echo "  verify DID SIG MESSAGE  Verify a signature for a message with the given DID"
    echo ""
    echo "Examples:"
    echo "  ./scripts/run_tool.sh generate"
    echo "  ./scripts/run_tool.sh sign did:key:z123 \"Hello World\""
    echo "  ./scripts/run_tool.sh verify did:key:z123 \"eyJhb...\" \"Hello World\""
}

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is required but not installed."
    exit 1
fi

# Check if Poetry is installed and project is set up
if ! command -v poetry &> /dev/null; then
    echo "Warning: Poetry is not installed. Will try to run directly with Python."
    HAS_POETRY=false
else
    HAS_POETRY=true
fi

# Run using Naptha CLI if available
run_with_naptha() {
    OPERATION=$1
    if [ "$OPERATION" = "generate" ]; then
        naptha run tool:vela_did_tool -p "operation='generate'"
    elif [ "$OPERATION" = "sign" ]; then
        DID=$2
        MESSAGE=$3
        naptha run tool:vela_did_tool -p "operation='sign' AGENT_DID='$DID' MESSAGE='$MESSAGE'"
    elif [ "$OPERATION" = "verify" ]; then
        DID=$2
        SIGNATURE=$3
        MESSAGE=$4
        naptha run tool:vela_did_tool -p "operation='verify' AGENT_DID='$DID' SIGNATURE='$SIGNATURE' MESSAGE='$MESSAGE'"
    else
        echo "Error: Unknown operation: $OPERATION"
        print_usage
        exit 1
    fi
}

# Run using Python directly
run_with_python() {
    OPERATION=$1
    
    # Set environment variables based on operation
    export INPUT_OPERATION="$OPERATION"
    
    if [ "$OPERATION" = "generate" ]; then
        # No additional parameters needed
        true
    elif [ "$OPERATION" = "sign" ]; then
        export INPUT_AGENT_DID="$2"
        export INPUT_MESSAGE="$3"
    elif [ "$OPERATION" = "verify" ]; then
        export INPUT_AGENT_DID="$2"
        export INPUT_SIGNATURE="$3"
        export INPUT_MESSAGE="$4"
    else
        echo "Error: Unknown operation: $OPERATION"
        print_usage
        exit 1
    fi
    
    # Run with Poetry if available, otherwise with Python directly
    if [ "$HAS_POETRY" = true ]; then
        poetry run python -m src.main
    else
        PYTHONPATH="$PROJECT_ROOT" python3 -m src.main
    fi
}

# Main execution
if [ $# -lt 1 ]; then
    print_usage
    exit 1
fi

OPERATION=$1
shift  # Remove the operation from the arguments

case "$OPERATION" in
    generate)
        # No additional parameters required
        ;;
    sign)
        if [ $# -lt 2 ]; then
            echo "Error: sign operation requires DID and MESSAGE parameters."
            print_usage
            exit 1
        fi
        ;;
    verify)
        if [ $# -lt 3 ]; then
            echo "Error: verify operation requires DID, SIGNATURE, and MESSAGE parameters."
            print_usage
            exit 1
        fi
        ;;
    help)
        print_usage
        exit 0
        ;;
    *)
        echo "Error: Unknown operation: $OPERATION"
        print_usage
        exit 1
        ;;
esac

# Run the tool
if [ "$HAS_NAPTHA" = true ]; then
    echo "Running with Naptha CLI..."
    run_with_naptha "$OPERATION" "$@"
else
    echo "Running with Python directly..."
    run_with_python "$OPERATION" "$@"
fi 