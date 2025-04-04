#!/usr/bin/env python3
"""
Test script for verifying the DIDKit API using the mock implementation.
This script tests the high-level DID utility functions against the
mock implementation to ensure the API works correctly.
"""

import os
import sys
import json
import logging
from typing import Dict, Any

# Set environment to use mock implementation
os.environ["VELA_PRODUCTION_MODE"] = "false"

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("test-mock-didkit")

def print_section(title: str):
    """Print a section header"""
    print("\n" + "="*60)
    print(f"  {title}")
    print("="*60)

def test_mock_didkit():
    """Test the DIDKit API using the mock implementation"""
    print_section("Importing did_utils")
    try:
        # Make sure the WASM file doesn't exist to force mock usage
        wasm_path = os.path.join(os.path.dirname(__file__), "src", "wasm", "didkit_compiled.wasm")
        if os.path.exists(wasm_path):
            os.rename(wasm_path, f"{wasm_path}.bak")
            print(f"Temporarily renamed WASM file to {wasm_path}.bak")
        
        # Import the did_utils module
        import src.did_utils as did_utils
        
        # Check if we're using the mock implementation
        if not did_utils.is_using_mock():
            print("❌ Not using mock implementation as expected")
            return False
        else:
            print("✅ Using mock implementation as expected")
    except Exception as e:
        print(f"❌ Failed to import did_utils: {e}")
        return False
    
    print_section("Testing Key Generation")
    try:
        # Generate a DID
        result = did_utils.generate_did()
        
        # Check the result
        if not isinstance(result, dict):
            print(f"❌ generate_did() didn't return a dictionary: {result}")
            return False
        
        if not all(k in result for k in ["did", "verificationMethod", "privateKeyJwk", "publicKeyJwk"]):
            print(f"❌ generate_did() returned incomplete data: {result}")
            return False
        
        did = result["did"]
        verification_method = result["verificationMethod"]
        private_key_jwk = result["privateKeyJwk"]
        
        print(f"✅ Generated DID: {did}")
        print(f"✅ Generated verificationMethod: {verification_method}")
        print(f"✅ Generated privateKeyJwk: {json.dumps(private_key_jwk)[:50]}...")
    except Exception as e:
        print(f"❌ Failed to generate DID: {e}")
        return False
    
    print_section("Testing Credential Creation")
    try:
        # Create a verifiable credential
        message = "Hello, DIDKit!"
        
        # Extract issuer DID from verification method
        issuer_did = verification_method.split("#")[0]
        subject_did = issuer_did  # Self-issued
        
        credential = did_utils.create_verifiable_credential(
            issuer_did=issuer_did,
            subject_did=subject_did,
            message=message
        )
        
        print(f"✅ Created credential: {json.dumps(credential, indent=2)}")
        
        # Check credential structure
        if not isinstance(credential, dict):
            print(f"❌ create_verifiable_credential() didn't return a dictionary: {credential}")
            return False
        
        if not all(k in credential for k in ["@context", "type", "issuer", "issuanceDate", "credentialSubject"]):
            print(f"❌ create_verifiable_credential() returned incomplete data: {credential}")
            return False
        
        if not isinstance(credential["credentialSubject"], dict) or credential["credentialSubject"].get("message") != message:
            print(f"❌ Credential subject doesn't contain the expected message: {credential['credentialSubject']}")
            return False
        
        print(f"✅ Credential structure verified")
    except Exception as e:
        print(f"❌ Failed to create credential: {e}")
        return False
    
    print_section("Testing Signing")
    try:
        # Sign a message
        message = "Hello, DIDKit!"
        signed_credential = did_utils.sign(
            private_key_jwk=private_key_jwk,
            verification_method=verification_method,
            message=message
        )
        
        # Check signed credential
        if not isinstance(signed_credential, str):
            print(f"❌ sign() didn't return a string: {signed_credential}")
            return False
        
        try:
            signed_credential_json = json.loads(signed_credential)
        except json.JSONDecodeError:
            print(f"❌ sign() didn't return valid JSON: {signed_credential}")
            return False
        
        if "proof" not in signed_credential_json:
            print(f"❌ Signed credential doesn't contain a proof: {signed_credential_json}")
            return False
        
        print(f"✅ Generated signed credential: {signed_credential[:100]}...")
    except Exception as e:
        print(f"❌ Failed to sign message: {e}")
        return False
    
    print_section("Testing Verification")
    try:
        # Verify the signed credential
        verification_result = did_utils.verify(signed_credential)
        
        # Check verification result
        if not isinstance(verification_result, dict):
            print(f"❌ verify() didn't return a dictionary: {verification_result}")
            return False
        
        if not verification_result.get("valid"):
            print(f"❌ Verification failed: {verification_result}")
            return False
        
        print(f"✅ Verification succeeded: {json.dumps(verification_result, indent=2)}")
    except Exception as e:
        print(f"❌ Failed to verify credential: {e}")
        return False
    
    print_section("Testing Composite Message")
    try:
        # Sign a composite message
        result_pointer = "result:abc123"
        code_id = "code:xyz789"
        
        signed_composite = did_utils.sign_composite(
            private_key_jwk=private_key_jwk,
            verification_method=verification_method,
            result_pointer=result_pointer,
            code_id=code_id
        )
        
        # Check signed composite
        if not isinstance(signed_composite, str):
            print(f"❌ sign_composite() didn't return a string: {signed_composite}")
            return False
        
        try:
            signed_composite_json = json.loads(signed_composite)
        except json.JSONDecodeError:
            print(f"❌ sign_composite() didn't return valid JSON: {signed_composite}")
            return False
        
        if "proof" not in signed_composite_json:
            print(f"❌ Signed composite doesn't contain a proof: {signed_composite_json}")
            return False
        
        # Extract composite values
        extracted_rp, extracted_code = did_utils.extract_composite_from_credential(signed_composite)
        if extracted_rp != result_pointer or extracted_code != code_id:
            print(f"❌ Extracted values don't match: got {extracted_rp}, {extracted_code}, expected {result_pointer}, {code_id}")
            return False
        
        print(f"✅ Generated signed composite: {signed_composite[:100]}...")
        print(f"✅ Extracted values match: {extracted_rp}, {extracted_code}")
    except Exception as e:
        print(f"❌ Failed to sign composite message: {e}")
        return False
    
    # Restore the WASM file if it was renamed
    if os.path.exists(f"{wasm_path}.bak"):
        os.rename(f"{wasm_path}.bak", wasm_path)
        print(f"Restored WASM file from {wasm_path}.bak")
    
    return True

if __name__ == "__main__":
    success = test_mock_didkit()
    if not success:
        print("\n❌ Mock DIDKit test failed")
        sys.exit(1)
    else:
        print("\n✅ Mock DIDKit test completed successfully")
        print("\nThe mock implementation appears to be working correctly.")
        print("This means the DIDKit API is correctly implemented in the did_utils module.")
        print("You can now implement the same API in a real WASM module with C-style exports.")
        sys.exit(0) 