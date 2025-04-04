"""
Mock implementation of didkit functions for development without WASM.
This is only for development and testing. In production, you need the actual WASM file.
"""

import json
import base64
import secrets
import time
import datetime
import logging
import uuid
import hashlib
from typing import Dict, Any, Optional, List

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vela-did-tool.mock_didkit")

# Sample Ed25519 key structure
SAMPLE_KEY_TEMPLATE = {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "",  # public key
    "d": ""   # private key
}

# Custom credential types
MOCK_MACHINE_CREDENTIAL_TYPE = "MachineCredential"
MOCK_AGENT_CREDENTIAL_TYPE = "AgentCredential"

class MockDidkitWasm:
    """
    Mock implementation of the DidkitWasm class for development and testing.
    This provides the same interface as DidkitWasm but with simplified mock functionality.
    """
    
    def __init__(self):
        """Initialize the mock didkit implementation."""
        logger.warning("🚨 Initializing MOCK didkit implementation - NOT FOR PRODUCTION USE 🚨")
    
    def generate_ed25519_key(self) -> Dict[str, Any]:
        """
        Generate a fake Ed25519 key for development purposes.
        
        Returns:
            The generated key as a JWK dict
        """
        logger.warning("🚨 Using MOCK key generation - NOT CRYPTOGRAPHICALLY SECURE 🚨")
        
        # These are not real Ed25519 keys, just random bytes for testing
        private_key = secrets.token_bytes(32)
        public_key = secrets.token_bytes(32)  # In reality, derived from private key
        
        private_key_b64 = base64.b64encode(private_key).decode('ascii')
        public_key_b64 = base64.b64encode(public_key).decode('ascii')
        
        jwk = SAMPLE_KEY_TEMPLATE.copy()
        jwk["d"] = private_key_b64
        jwk["x"] = public_key_b64
        
        return jwk
    
    def key_to_did(self, method: str, jwk: Dict[str, Any]) -> str:
        """
        Convert a JWK to a DID using the specified method.
        
        Args:
            method: The DID method (e.g., "key")
            jwk: The JWK dict
            
        Returns:
            The DID string
        """
        logger.warning("🚨 Using MOCK DID generation - NOT CRYPTOGRAPHICALLY SECURE 🚨")
        
        # Use the 'x' component from the JWK
        x_value = jwk.get("x", "")
        if not x_value:
            raise ValueError("JWK missing 'x' value")
        
        # Try to decode it if it's base64, otherwise use it as-is
        try:
            x_bytes = base64.b64decode(x_value)
        except:
            x_bytes = x_value.encode('utf-8')
        
        # Use x_bytes to create a deterministic but fake DID
        # For did:key, we prefix with z to mock multibase encoding
        mock_did = f"did:{method}:z{base64.b32encode(x_bytes[:10]).decode('ascii').lower()}"
        
        return mock_did
    
    def key_to_verification_method(self, method: str, jwk: Dict[str, Any]) -> str:
        """
        Convert a JWK to a verification method DID URL.
        
        Args:
            method: The DID method (e.g., "key")
            jwk: The JWK dict
            
        Returns:
            The verification method DID URL
        """
        did = self.key_to_did(method, jwk)
        
        # For did:key, the verification method is the same as the DID with a fragment
        # that's also the same as the DID without the prefix
        if method == "key":
            vm = f"{did}#{did.replace('did:key:', '')}"
        else:
            # For other methods, just append a generic fragment
            vm = f"{did}#keys-1"
            
        return vm
    
    def issue_credential(self, credential: Dict[str, Any], options: Dict[str, Any],
                         key: Dict[str, Any]) -> Dict[str, Any]:
        """
        Issue a Verifiable Credential by adding a mock proof.
        
        Args:
            credential: The unsigned credential as a dict
            options: Proof options as a dict
            key: The signing key as a JWK dict
            
        Returns:
            The signed credential as a dict
        """
        logger.warning("🚨 Using MOCK credential issuance - NOT CRYPTOGRAPHICALLY SECURE 🚨")
        
        # Clone the credential to avoid modifying the original
        signed_cred = credential.copy()
        
        # Create a verification method if not specified in options
        verification_method = options.get("verificationMethod")
        if not verification_method:
            method = "key"  # Default to did:key method
            verification_method = self.key_to_verification_method(method, key)
        
        # Add credential ID if missing
        if "id" not in signed_cred:
            signed_cred["id"] = f"urn:uuid:{uuid.uuid4()}"
        
        # Ensure issuer is present
        if "issuer" not in signed_cred:
            # Extract issuer DID from verification method
            issuer_did = verification_method.split("#")[0]
            signed_cred["issuer"] = issuer_did
        
        # Ensure subject has ID if credential subject exists but lacks ID
        if "credentialSubject" in signed_cred and "id" not in signed_cred["credentialSubject"]:
            # Self-issued credential by default (subject is same as issuer)
            if isinstance(signed_cred["issuer"], str):
                signed_cred["credentialSubject"]["id"] = signed_cred["issuer"]
            else:
                # Handle case where issuer is an object
                signed_cred["credentialSubject"]["id"] = signed_cred["issuer"].get("id", "unknown")
        
        # Ensure type includes our custom credential types
        if "type" in signed_cred and isinstance(signed_cred["type"], list):
            if MOCK_MACHINE_CREDENTIAL_TYPE not in signed_cred["type"]:
                signed_cred["type"].append(MOCK_MACHINE_CREDENTIAL_TYPE)
            if MOCK_AGENT_CREDENTIAL_TYPE not in signed_cred["type"]:
                signed_cred["type"].append(MOCK_AGENT_CREDENTIAL_TYPE)
        
        # Create a current timestamp
        now = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        
        # Create a deterministic but fake signature
        # In a real implementation, this would be a cryptographic signature 
        # over the canonicalized credential
        cred_str = json.dumps(credential, sort_keys=True)
        fake_sig_input = (key.get("d", "") + cred_str).encode('utf-8')
        
        # Use hashlib instead of hash() to avoid the negative int issue
        sha256_hash = hashlib.sha256(fake_sig_input).digest()
        sig_value = base64.b64encode(sha256_hash).decode('ascii')
        
        # Add the proof
        proof = {
            "type": "Ed25519Signature2020",
            "created": now,
            "verificationMethod": verification_method,
            "proofPurpose": options.get("proofPurpose", "assertionMethod"),
            "proofValue": sig_value
        }
        
        # Add the proof to the credential
        signed_cred["proof"] = proof
        
        return signed_cred
    
    def verify_credential(self, credential: Dict[str, Any], options: Dict[str, Any]) -> Dict[str, Any]:
        """
        Verify a Verifiable Credential with a mock verification.
        
        Args:
            credential: The credential to verify as a dict
            options: Verification options as a dict
            
        Returns:
            The verification result as a dict
        """
        logger.warning("🚨 Using MOCK credential verification - NOT CRYPTOGRAPHICALLY SECURE 🚨")
        
        # Basic checks
        if not isinstance(credential, dict):
            return {"errors": ["Credential is not a valid dictionary"]}
        
        if "proof" not in credential:
            return {"errors": ["Credential has no proof"]}
        
        # Check for required fields in credential
        required_fields = ["@context", "type", "issuer", "issuanceDate"]
        missing_fields = [f for f in required_fields if f not in credential]
        if missing_fields:
            return {"errors": [f"Credential missing required fields: {', '.join(missing_fields)}"]}
        
        # Check for credentialSubject
        if "credentialSubject" not in credential:
            return {"errors": ["Credential missing credentialSubject"]}
        
        # Check if credentialSubject has an id field
        if "id" not in credential.get("credentialSubject", {}):
            return {"warnings": ["credentialSubject missing id property"]}
        
        # Check expiration if present
        if "expirationDate" in credential:
            try:
                exp_date = datetime.datetime.fromisoformat(credential["expirationDate"].replace("Z", "+00:00"))
                now = datetime.datetime.now(datetime.timezone.utc)
                if exp_date < now:
                    return {"errors": ["Credential has expired"]}
            except (ValueError, TypeError) as e:
                return {"errors": [f"Invalid expirationDate format: {e}"]}
        
        # In mock mode, we don't actually verify the cryptographic signature
        # We just check if the proof structure seems valid
        proof = credential.get("proof", {})
        proof_required_fields = ["type", "created", "verificationMethod", "proofPurpose", "proofValue"]
        
        missing_fields = [f for f in proof_required_fields if f not in proof]
        if missing_fields:
            return {"errors": [f"Proof missing required fields: {', '.join(missing_fields)}"]}
        
        # Check if the verification method matches what's in the options (if specified)
        if options.get("verificationMethod") and options["verificationMethod"] != proof["verificationMethod"]:
            return {"errors": ["Verification method in proof doesn't match the expected one"]}
        
        # Check if the proof purpose matches what's in the options (if specified)
        if options.get("proofPurpose") and options["proofPurpose"] != proof["proofPurpose"]:
            return {"errors": ["Proof purpose doesn't match the expected one"]}
        
        # In a mock implementation, we can't actually verify the signature cryptographically
        # So we assume it's valid if all the structural checks passed
        logger.warning("⚠️ MOCK verification - cryptographic signature verification SKIPPED ⚠️")
        
        return {
            "checks": ["proof"],
            "warnings": ["Mock verification does not validate cryptographic signatures"],
            "errors": []
        }
    
    def resolve_did(self, did: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Resolve a DID to a DID document with mock resolution.
        
        Args:
            did: The DID to resolve
            options: Resolution options (optional)
            
        Returns:
            The DID document as a dict
        """
        logger.warning("🚨 Using MOCK DID resolution - NOT CRYPTOGRAPHICALLY SECURE 🚨")
        
        if not did.startswith("did:"):
            raise ValueError(f"Invalid DID format: {did}")
        
        # Extract the method and ID parts
        parts = did.split(":")
        if len(parts) < 3:
            raise ValueError(f"Invalid DID format: {did}")
        
        method = parts[1]
        id_value = ":".join(parts[2:])
        
        # For did:key method, create a mock DID document
        if method == "key":
            verification_method = []
            
            # For did:key, the verification method ID is usually the DID with a fragment
            vm_id = f"{did}#{id_value}"
            
            vm = {
                "id": vm_id,
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyMultibase": id_value
            }
            
            verification_method.append(vm)
            
            return {
                "@context": "https://w3id.org/did/v1",
                "id": did,
                "verificationMethod": verification_method,
                "authentication": [vm_id],
                "assertionMethod": [vm_id]
            }
        else:
            # For other methods, return a generic DID document
            return {
                "@context": "https://w3id.org/did/v1",
                "id": did,
                "verificationMethod": [],
                "authentication": [],
                "assertionMethod": []
            } 