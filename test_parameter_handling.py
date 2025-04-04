#!/usr/bin/env python3
"""
Test script for demonstrating parameter handling in vela-did-tool.
This shows how parameters are passed from Naptha to the tool.
"""

import json
import os
import argparse
import tempfile
from typing import Dict, Any

def test_parameter_formats():
    """Test different ways parameters can be passed to vela-did-tool."""
    
    # Create a temporary JSON file with test parameters
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json_params = {
            "operation": "sign",
            "agent_did": "did:key:z3T6gKW...",
            "message": "Hello from JSON file"
        }
        json.dump(json_params, f)
        json_file_path = f.name
    
    print("\n===== Parameter Passing in vela-did-tool =====\n")
    
    print("1. Command-line Arguments:")
    print("   Example: python src/main.py --operation sign --agent-did did:key:z3T6gKW... --message 'Hello'")
    print("   → This is the most direct method when running the tool manually")
    
    print("\n2. JSON File:")
    print(f"   File contents: {json.dumps(json_params, indent=2)}")
    print("   Two ways to use:")
    print(f"   a. python src/main.py --input-file {json_file_path}")
    print(f"   b. export INPUT_FILE={json_file_path} && python src/main.py")
    print("   → This is useful for complex parameters or when called from another system")
    
    print("\n3. Environment Variables (development only):")
    print("   export INPUT_OPERATION=sign")
    print("   export INPUT_AGENT_DID=did:key:z3T6gKW...")
    print("   export INPUT_MESSAGE='Hello from env'")
    print("   python src/main.py")
    print("   → This is primarily for development/testing")
    
    print("\n4. Naptha SDK Integration:")
    print("   When called via Naptha's SDK, parameters are passed as:")
    print("   await tool.run(ToolRunInput(")
    print("       operation='sign',")
    print("       agent_did='did:key:z3T6gKW...',")
    print("       message='Hello from Naptha'")
    print("   ))")
    print("   → These are delivered to the tool by the Node's runtime")
    
    print("\n5. Naptha CLI usage:")
    print("   naptha run tool:vela_did_tool -p \"operation='sign' agent_did='did:key:z3T6gKW...' message='Hello'\"")
    print("   → The CLI parses this string and converts it to parameters")
    
    # Clean up the temporary file
    os.unlink(json_file_path)
    
    print("\n===== Secrets API Integration =====\n")
    
    print("1. Key Generation:")
    print("   Tool returns privateKeyJwk in the response:")
    print("   {")
    print("     \"status\": \"success\",")
    print("     \"did\": \"did:key:z3T6gKW...\",")
    print("     \"privateKeyJwk\": { \"kty\": \"OKP\", \"crv\": \"Ed25519\", ... },")
    print("     ...")
    print("   }")
    
    print("\n2. Key Provisioning:")
    print("   User/caller provisions the key:")
    print("   naptha deploy-secrets --name vela_agent_private_key_did_key_z3T6gKW... --value '{\"kty\":\"OKP\",...}'")
    
    print("\n3. Key Retrieval:")
    print("   Tool retrieves key during sign operations:")
    print("   secret_name = get_secret_name(agent_did)")
    print("   private_key = await get_secret(secret_name)")
    
    print("\n===== Testing Your Installation =====\n")
    
    print("To test if your installation is working correctly:")
    print("1. Generate a DID:")
    print("   naptha run tool:vela_did_tool -p \"operation='generate'\"")
    print("2. Deploy the privateKeyJwk as a secret")
    print("3. Sign a message:")
    print("   naptha run tool:vela_did_tool -p \"operation='sign' agent_did='YOUR_DID' message='Test message'\"")
    print("4. Verify the signature:")
    print("   naptha run tool:vela_did_tool -p \"operation='verify' signed_credential='YOUR_SIGNED_CREDENTIAL'\"")
    
    print("\nNote: In production, set VELA_PRODUCTION_MODE=true to ensure security.")

if __name__ == "__main__":
    test_parameter_formats() 