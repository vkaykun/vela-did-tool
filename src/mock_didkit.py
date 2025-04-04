"""
Mock implementation of DIDKit functions for development purposes only.
This module should NEVER be used in production environments.
It provides simple stubs for the DIDKit functionality that doesn't 
perform actual cryptographic operations.

In production mode, importing this file will raise an exception.
"""

# Import production guard to abort if in production mode
from .production_guard import fail_in_production, PRODUCTION_MODE

# Immediately abort if in production mode
if PRODUCTION_MODE:
    fail_in_production("mock_didkit.py was imported in production mode!")

import json
import time
import uuid
from typing import Dict, Any, Optional

# Keep the rest of the mock implementation intact
# Mock key for development purposes only - DO NOT USE IN PRODUCTION
MOCK_KEY = {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "MOCK_ED25519_PUBLIC_KEY_FOR_DEVELOPMENT_ONLY",
    "d": "MOCK_ED25519_PRIVATE_KEY_FOR_DEVELOPMENT_ONLY"
}

MOCK_DID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
MOCK_VERIFICATION_METHOD = f"{MOCK_DID}#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"

def generate_ed25519_key() -> Dict[str, Any]:
    """
    Mock implementation of didkit's key generation.
    Returns a mock key instead of generating a real one.
    
    Returns:
        Mock JWK as a dictionary
    """
    print("WARNING: Using MOCK key generation - NOT SECURE FOR PRODUCTION!")
    # Add a random suffix to the mock key to make it unique
    unique_mock = MOCK_KEY.copy()
    unique_mock['x'] = f"{unique_mock['x']}_{str(uuid.uuid4())[:8]}"
    unique_mock['d'] = f"{unique_mock['d']}_{str(uuid.uuid4())[:8]}"
    return unique_mock

def key_to_did(key_jwk: Dict[str, Any], method: str = "key") -> str:
    """
    Mock implementation of didkit's key_to_did.
    Returns a mock DID instead of generating a real one.
    
    Args:
        key_jwk: JWK representation of the key
        method: DID method (e.g., "key")
        
    Returns:
        Mock DID
    """
    print("WARNING: Using MOCK DID generation - NOT SECURE FOR PRODUCTION!")
    # Add a random suffix to the mock DID to make it unique
    unique_id = str(uuid.uuid4())[:8]
    if method == "key":
        return f"{MOCK_DID}_{unique_id}"
    else:
        return f"did:{method}:mock_{unique_id}"

def key_to_verification_method(key_jwk: Dict[str, Any], method: str = "key") -> str:
    """
    Mock implementation of didkit's key_to_verification_method.
    Returns a mock verification method instead of generating a real one.
    
    Args:
        key_jwk: JWK representation of the key
        method: DID method (e.g., "key")
        
    Returns:
        Mock verification method URI
    """
    print("WARNING: Using MOCK verification method - NOT SECURE FOR PRODUCTION!")
    did = key_to_did(key_jwk, method)
    # Extract the key ID from the mock DID
    key_id = did.replace(f"did:{method}:", "")
    return f"{did}#{key_id}"

def issue_credential(credential: Dict[str, Any], proof_options: Dict[str, Any], key_jwk: Dict[str, Any]) -> Dict[str, Any]:
    """
    Mock implementation of didkit's issue_credential.
    Returns the credential with a mock proof instead of a real signature.
    
    Args:
        credential: Credential to sign
        proof_options: Options for the proof
        key_jwk: Key to sign with
        
    Returns:
        Credential with mock proof
    """
    print("WARNING: Using MOCK credential issuance - NOT SECURE FOR PRODUCTION!")
    # Deep copy the credential to avoid modifying the original
    signed_credential = json.loads(json.dumps(credential))
    
    # Create a mock proof
    proof = {
        "type": "Ed25519Signature2018",
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "verificationMethod": proof_options.get("verificationMethod", MOCK_VERIFICATION_METHOD),
        "proofPurpose": proof_options.get("proofPurpose", "assertionMethod"),
        "proofValue": f"mockProof{str(uuid.uuid4())}"
    }
    
    # Add proof to credential
    signed_credential["proof"] = proof
    return signed_credential

def verify_credential(credential: Dict[str, Any], verify_options: Dict[str, Any]) -> Dict[str, Any]:
    """
    Mock implementation of didkit's verify_credential.
    Always returns a successful verification result.
    
    Args:
        credential: Credential to verify
        verify_options: Options for verification
        
    Returns:
        Mock verification result
    """
    print("WARNING: Using MOCK credential verification - NOT SECURE FOR PRODUCTION!")
    # Always return successful verification in mock mode
    return {
        "valid": True,
        "format": "json_ld" if isinstance(credential, dict) and "proof" in credential else "jwt",
        "details": "Mock verification always succeeds. DO NOT USE IN PRODUCTION!"
    }

def resolve_did(did: str) -> Dict[str, Any]:
    """
    Mock implementation of didkit's resolve_did.
    Returns a mock DID document.
    
    Args:
        did: DID to resolve
        
    Returns:
        Mock DID resolution result
    """
    print("WARNING: Using MOCK DID resolution - NOT SECURE FOR PRODUCTION!")
    
    verification_method_id = f"{did}#{did.split('did:')[1].split(':')[1]}"
    
    # Create a mock DID document
    did_document = {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [{
            "id": verification_method_id,
            "type": "Ed25519VerificationKey2018",
            "controller": did,
            "publicKeyBase58": "MOCK_PUBLIC_KEY_BASE58"
        }],
        "authentication": [verification_method_id],
        "assertionMethod": [verification_method_id]
    }
    
    # Create a mock DID resolution result
    return {
        "didDocument": did_document,
        "didResolutionMetadata": {
            "contentType": "application/did+ld+json"
        },
        "didDocumentMetadata": {}
    } 