"""
High-level utility functions for DID operations.
This module provides a clean API for generating DIDs, signing, and verifying.

# W3C Verifiable Credentials Structure
This implementation follows the W3C Verifiable Credentials Data Model 1.0:
https://www.w3.org/TR/vc-data-model/

Key structural elements and their security significance:

1. @context: Defines the vocabulary and data types used in the credential.
   Required for interoperability and proper interpretation of fields.

2. id: A unique identifier for the credential itself.
   Important for revocation and reference.

3. type: Defines what kind of credential this is.
   Must include "VerifiableCredential" plus any additional specific types.

4. issuer: The DID of the entity that issued the credential.
   CRITICAL for verification - defines who made the claim and whose
   signature should be checked.

5. issuanceDate: When the credential was issued.
   Used for validity period calculations and freshness assessment.

6. expirationDate: When the credential expires.
   Key for automatic credential rotation and security.

7. credentialSubject: Contains the actual claims.
   - id: DID of the subject (entity the claim is about)
     CRITICAL FOR SECURITY - binds the claim to a specific entity,
     preventing credential misuse or transfer to other entities.
   - claims: The actual data being attested to.

8. proof: Added when signed, contains signature and metadata.
   - type: Signature algorithm/suite used.
   - proofPurpose: Why this proof exists (e.g., "assertionMethod").
   - verificationMethod: DID URL pointing to the specific key used.
   - created: When the signature was created.
   - jws/proofValue: The actual signature value.

Security note: For proper security, both the issuer and credentialSubject.id
are required. Self-issued credentials (where issuer == credentialSubject.id)
are used for assertions about one's own identity or attributes.
"""

import os
import json
import logging
import datetime
import time
import hashlib
import uuid
from typing import Dict, Optional, Any, Tuple, List, Union

# Import the production guard
from .production_guard import PRODUCTION_MODE, fail_in_production, guard_import

# Import custom error types
from .errors import (
    VelaError,
    WasmIntegrityError,
    WasmLoadError,
    DidGenerationError,
    DidResolutionError,
    SigningError,
    VerificationError,
    CredentialFormatError,
    CredentialParseError,
    SelfTestError,
    ProductionGuardError
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vela-did-tool.did_utils")

# Global flag to track if we're using mock implementation
_using_mock = False

# Expected WASM file hash - set this to the known hash of your trusted WASM file
# This is a SHA-256 hash - update this when you deploy a new version
EXPECTED_WASM_HASH = os.environ.get("VELA_WASM_HASH", "")  

# Days until credential expiration (default 90 days)
DEFAULT_EXPIRATION_DAYS = int(os.environ.get("VELA_CREDENTIAL_EXPIRATION_DAYS", "90"))

# Custom credential types
MACHINE_CREDENTIAL_TYPE = "MachineCredential"
AGENT_CREDENTIAL_TYPE = "AgentCredential"

def _verify_wasm_integrity() -> Tuple[bool, str]:
    """
    Verify the integrity of the WASM file by checking its hash.
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not EXPECTED_WASM_HASH:
        if PRODUCTION_MODE:
            return False, "WASM hash check is mandatory in production mode but VELA_WASM_HASH is not set"
        else:
            logger.warning("WASM hash check disabled (VELA_WASM_HASH not set)")
            return True, ""
            
    wasm_path = os.path.join(os.path.dirname(__file__), "wasm", "didkit_compiled.wasm")
    
    if not os.path.exists(wasm_path):
        return False, f"WASM file not found at {wasm_path}"
        
    try:
        with open(wasm_path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
            
        if file_hash != EXPECTED_WASM_HASH:
            return False, f"WASM file integrity check failed! Expected {EXPECTED_WASM_HASH}, got {file_hash}"
            
        logger.info(f"WASM file integrity verified (SHA-256: {file_hash})")
        return True, ""
    except Exception as e:
        return False, f"Error verifying WASM file: {e}"

# Initialize the DIDKit WASM interface
try:
    # In production mode, enforce WASM hash check
    if PRODUCTION_MODE:
        is_valid, error_msg = _verify_wasm_integrity()
        if not is_valid:
            logger.error(error_msg)
            raise WasmIntegrityError(f"WASM integrity verification failed: {error_msg}")
    
    # Import the WASM wrapper directly - no fallback to mock in production
    from .wasm_wrapper import DidkitWasm
    _didkit = DidkitWasm()
    logger.info("Initialized DIDKit WASM interface successfully")
    
    # Perform a self-test in production mode
    if PRODUCTION_MODE:
        try:
            logger.info("Performing DIDKit self-test...")
            # Force import here to avoid circular imports
            from . import did_utils
            did_utils.perform_self_test()
            logger.info("DIDKit self-test passed successfully")
        except Exception as e:
            error_msg = f"DIDKit self-test failed: {e}"
            logger.error(error_msg)
            raise SelfTestError(error_msg)
    
except Exception as e:
    error_msg = f"Failed to initialize DIDKit WASM: {e}"
    
    # In production mode, we never allow fallback to mock implementations
    if PRODUCTION_MODE:
        logger.critical(f"{error_msg} - Cannot fall back to mock in production mode")
        raise WasmLoadError(error_msg)
    else:
        # Only in development mode can we use the mock implementation
        logger.warning(f"{error_msg} - Falling back to mock implementation")
        
        # Use the guard_import to ensure we can't import mocks in production
        mock_module = guard_import(".wasm.mock_didkit")
        if mock_module is None:
            raise ImportError("Failed to import mock implementation")
            
        MockDidkitWasm = mock_module.MockDidkitWasm
        _didkit = MockDidkitWasm()
        _using_mock = True
        logger.warning("SECURITY WARNING: Using mock DID implementation - NOT SECURE FOR PRODUCTION")

# Production safety check - if we're in production but ended up with mock, abort
if PRODUCTION_MODE and _using_mock:
    fail_in_production("Using mock DID implementation in production mode")

def perform_self_test() -> None:
    """
    Perform a self-test to ensure DIDKit is working correctly.
    This generates a test key, issues a test credential, and verifies it.
    
    Raises:
        SelfTestError: If any part of the test fails
    """
    # Only run test with real implementation
    if _using_mock:
        logger.warning("Skipping self-test with mock implementation")
        return
        
    start_time = time.time()
    try:
        # 1. Generate a test key
        test_key = _didkit.generate_ed25519_key()
        if not test_key or not isinstance(test_key, dict) or 'kty' not in test_key:
            raise SelfTestError("Failed to generate test key")
        
        # 2. Derive DID and verification method
        test_did = _didkit.key_to_did("key", test_key)
        test_vm = _didkit.key_to_verification_method("key", test_key)
        if not test_did or not test_vm:
            raise SelfTestError("Failed to derive DID or verification method")
        
        # 3. Create a test credential
        test_cred = {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential", "TestCredential"],
            "issuer": test_did,
            "issuanceDate": datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
            "credentialSubject": {
                "id": test_did,
                "test": "This is a self-test credential"
            }
        }
        
        # 4. Issue the credential
        proof_options = {
            "proofPurpose": "assertionMethod",
            "verificationMethod": test_vm
        }
        signed_cred = _didkit.issue_credential(test_cred, proof_options, test_key)
        if not signed_cred or not isinstance(signed_cred, dict) or 'proof' not in signed_cred:
            raise SelfTestError("Failed to issue test credential")
        
        # 5. Verify the credential
        verify_options = {"proofPurpose": "assertionMethod"}
        verify_result = _didkit.verify_credential(signed_cred, verify_options)
        
        if not verify_result or not isinstance(verify_result, dict):
            raise SelfTestError("Failed to verify test credential")
            
        # Check if verification was successful (empty errors array)
        if len(verify_result.get("errors", [])) > 0:
            raise SelfTestError(f"Test credential verification failed: {verify_result}")
            
        duration = time.time() - start_time
        logger.info(f"Self-test completed successfully in {duration:.2f} seconds")
    except Exception as e:
        logger.error(f"Self-test failed: {e}")
        raise SelfTestError(f"DIDKit self-test failed: {e}")

def is_using_mock() -> bool:
    """
    Returns True if using mock implementation.
    """
    return _using_mock

def validate_credential_structure(credential: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Validate that a credential has required W3C fields.
    
    This function checks if a credential complies with the W3C Verifiable Credentials
    Data Model by validating the presence of required fields.
    
    Args:
        credential: The credential to validate
        
    Returns:
        A tuple of (is_valid, [list_of_issues])
    """
    issues = []
    
    # Check required top-level fields
    required_fields = ["@context", "type", "issuer", "issuanceDate", "credentialSubject"]
    for field in required_fields:
        if field not in credential:
            issues.append(f"Missing required field: {field}")
    
    # Check context includes the base VC context
    if "@context" in credential:
        contexts = credential["@context"]
        if not isinstance(contexts, list):
            contexts = [contexts]
        
        if "https://www.w3.org/2018/credentials/v1" not in contexts:
            issues.append("Missing base context: https://www.w3.org/2018/credentials/v1")
    
    # Check types include VerifiableCredential
    if "type" in credential:
        types = credential["type"]
        if not isinstance(types, list):
            types = [types]
            
        if "VerifiableCredential" not in types:
            issues.append("Missing required type: VerifiableCredential")
    
    # Check credentialSubject has an id field
    if "credentialSubject" in credential:
        subject = credential["credentialSubject"]
        if not isinstance(subject, dict):
            issues.append("credentialSubject must be an object")
        elif "id" not in subject:
            issues.append("Missing credentialSubject.id - recommended for security")
    
    return (len(issues) == 0, issues)

def get_wasm_integrity_status() -> Dict[str, Any]:
    """
    Get the status of WASM integrity verification.
    
    Returns:
        Dictionary with integrity check info
    """
    wasm_path = os.path.join(os.path.dirname(__file__), "wasm", "didkit_compiled.wasm")
    result = {
        "checkPerformed": False,
        "fileExists": os.path.exists(wasm_path),
        "hashVerified": False,
        "expectedHash": EXPECTED_WASM_HASH,
    }
    
    if result["fileExists"] and EXPECTED_WASM_HASH:
        result["checkPerformed"] = True
        with open(wasm_path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
            result["actualHash"] = file_hash
            result["hashVerified"] = file_hash == EXPECTED_WASM_HASH
    
    return result

def generate_did() -> Dict[str, Any]:
    """
    Generate a new DID:key with associated Ed25519 key pair.
    
    Returns:
        A dictionary with 'did', 'privateKeyJwk', and 'publicKeyJwk'
        
    Raises:
        DidGenerationError: If DID generation fails
    """
    try:
        # Generate Ed25519 key
        key_jwk = _didkit.generate_ed25519_key()
        
        # Convert to DID
        did = _didkit.key_to_did("key", key_jwk)
        
        # Get verification method (needed for signing)
        verification_method = _didkit.key_to_verification_method("key", key_jwk)
        
        # Extract public key parts (without the private 'd' component)
        public_key_jwk = {k: v for k, v in key_jwk.items() if k != 'd'}
        
        return {
            "did": did,
            "verificationMethod": verification_method,
            "privateKeyJwk": key_jwk,
            "publicKeyJwk": public_key_jwk
        }
        
    except Exception as e:
        logger.error(f"Error generating DID: {e}")
        raise DidGenerationError(f"Failed to generate DID: {e}")

def create_verifiable_credential(issuer_did: str, subject_did: str, message: str, 
                                expiration_days: int = DEFAULT_EXPIRATION_DAYS) -> Dict[str, Any]:
    """
    Create an unsigned Verifiable Credential containing a message.
    
    This function creates a W3C-compliant Verifiable Credential with proper binding
    between the issuer and subject using DIDs, following the W3C recommendation for
    credential structure.
    
    Args:
        issuer_did: The DID of the issuer (entity making the claim)
        subject_did: The DID of the subject (entity the claim is about)
        message: The message to include in the credential
        expiration_days: Number of days until credential expires (default 90)
        
    Returns:
        An unsigned Verifiable Credential as a dict
    """
    # Get current time in ISO format
    now = datetime.datetime.utcnow().replace(microsecond=0)
    issuance_date = now.isoformat() + "Z"
    
    # Calculate expiration date (if requested)
    expiration_date = None
    if expiration_days > 0:
        expiration_date = (now + datetime.timedelta(days=expiration_days)).isoformat() + "Z"
    
    # Generate a unique credential ID
    credential_id = f"urn:uuid:{uuid.uuid4()}"
    
    # Create a VC with proper structure
    credential = {
        # Context is crucial for defining the credential vocabulary
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            # Add security context for proper proof validation
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        # Unique identifier for this credential instance
        "id": credential_id,
        # Type defines what kind of credential this is
        "type": ["VerifiableCredential", MACHINE_CREDENTIAL_TYPE, AGENT_CREDENTIAL_TYPE],
        # Issuer is REQUIRED by W3C spec - identifies who is making the claim
        # This is crucial for verification and trust models
        "issuer": issuer_did,
        # IssuanceDate is REQUIRED by W3C spec
        "issuanceDate": issuance_date,
        # CredentialSubject contains the actual claims
        "credentialSubject": {
            # Subject ID is RECOMMENDED by W3C - binds credential to a specific entity
            # This is crucial for security, as it prevents credential reuse for other entities
            "id": subject_did,
            # The actual claim/message
            "message": message
        }
    }
    
    # Add expiration date if specified
    if expiration_date:
        credential["expirationDate"] = expiration_date
    
    return credential

def create_composite_credential(issuer_did: str, subject_did: str, result_pointer: str, code_id: str,
                                expiration_days: int = DEFAULT_EXPIRATION_DAYS) -> Dict[str, Any]:
    """
    Create an unsigned Verifiable Credential containing resultPointer and codeId.
    
    This function creates a W3C-compliant Verifiable Credential with proper binding
    between the issuer and subject using DIDs, following the W3C recommendation for
    credential structure. The composite credential specifically includes computational
    result information using resultPointer and codeId fields.
    
    Args:
        issuer_did: The DID of the issuer (entity making the claim)
        subject_did: The DID of the subject (entity the claim is about)
        result_pointer: The result pointer value (reference to computation result)
        code_id: The code ID value (reference to the code that produced the result)
        expiration_days: Number of days until credential expires (default 90)
        
    Returns:
        An unsigned Verifiable Credential as a dict
    """
    # Get current time in ISO format
    now = datetime.datetime.utcnow().replace(microsecond=0)
    issuance_date = now.isoformat() + "Z"
    
    # Calculate expiration date (if requested)
    expiration_date = None
    if expiration_days > 0:
        expiration_date = (now + datetime.timedelta(days=expiration_days)).isoformat() + "Z"
    
    # Generate a unique credential ID
    credential_id = f"urn:uuid:{uuid.uuid4()}"
    
    # Create a VC with proper structure
    credential = {
        # Context is crucial for defining the credential vocabulary
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            # Add security context for proper proof validation
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        # Unique identifier for this credential instance
        "id": credential_id,
        # Type defines what kind of credential this is
        "type": ["VerifiableCredential", MACHINE_CREDENTIAL_TYPE, AGENT_CREDENTIAL_TYPE],
        # Issuer is REQUIRED by W3C spec - identifies who is making the claim
        # This is crucial for verification and trust models
        "issuer": issuer_did,
        # IssuanceDate is REQUIRED by W3C spec
        "issuanceDate": issuance_date,
        # CredentialSubject contains the actual claims
        "credentialSubject": {
            # Subject ID is RECOMMENDED by W3C - binds credential to a specific entity
            # This is crucial for security, as it prevents credential reuse for other entities
            "id": subject_did,
            # The actual claims for this composite credential
            "resultPointer": result_pointer,
            "codeId": code_id
        }
    }
    
    # Add expiration date if specified
    if expiration_date:
        credential["expirationDate"] = expiration_date
    
    return credential

def sign(private_key_jwk: Dict[str, Any], verification_method: str, message: str,
         expiration_days: int = DEFAULT_EXPIRATION_DAYS) -> str:
    """
    Sign a message using the provided private key.
    This creates a Verifiable Credential with the message and signs it.
    
    Args:
        private_key_jwk: The JWK private key dictionary
        verification_method: The verification method URI (DID URL with fragment)
        message: The message to sign
        expiration_days: Number of days until credential expires (default 90)
        
    Returns:
        A signed Verifiable Credential as a JSON string
        
    Raises:
        SigningError: If signing fails
    """
    try:
        # Extract issuer DID from verification method
        issuer_did = verification_method.split("#")[0]
        
        # Create an unsigned Verifiable Credential
        # For self-issued credentials, subject is same as issuer
        unsigned_vc = create_verifiable_credential(issuer_did, issuer_did, message, expiration_days)
        
        # Validate credential structure before signing
        is_valid, issues = validate_credential_structure(unsigned_vc)
        if not is_valid:
            logger.warning(f"Unsigned credential has structural issues: {issues}")
            # Continue despite issues
        
        # Proof options
        proof_options = {
            "proofPurpose": "assertionMethod",
            "verificationMethod": verification_method
        }
        
        # Issue (sign) the credential
        signed_vc = _didkit.issue_credential(unsigned_vc, proof_options, private_key_jwk)
        
        # Return the signed credential as a JSON string
        return json.dumps(signed_vc)
        
    except Exception as e:
        logger.error(f"Error signing message: {e}")
        raise SigningError(f"Failed to sign message: {e}")

def sign_composite(private_key_jwk: Dict[str, Any], verification_method: str, 
                  result_pointer: str, code_id: str,
                  expiration_days: int = DEFAULT_EXPIRATION_DAYS) -> str:
    """
    Sign a composite message (resultPointer + codeId) using the provided private key.
    This creates a Verifiable Credential with both values and signs it.
    
    Args:
        private_key_jwk: The JWK private key dictionary
        verification_method: The verification method URI (DID URL with fragment)
        result_pointer: The result pointer value (reference to computation result)
        code_id: The code ID value (reference to the code that produced the result)
        expiration_days: Number of days until credential expires (default 90)
        
    Returns:
        A signed Verifiable Credential as a JSON string
        
    Raises:
        SigningError: If signing fails
    """
    try:
        # Extract issuer DID from verification method
        issuer_did = verification_method.split("#")[0]
        
        # Create an unsigned Verifiable Credential with both values
        # For self-issued credentials, subject is same as issuer
        unsigned_vc = create_composite_credential(issuer_did, issuer_did, result_pointer, code_id, expiration_days)
        
        # Validate credential structure before signing
        is_valid, issues = validate_credential_structure(unsigned_vc)
        if not is_valid:
            logger.warning(f"Unsigned composite credential has structural issues: {issues}")
            # Continue despite issues
        
        # Proof options
        proof_options = {
            "proofPurpose": "assertionMethod",
            "verificationMethod": verification_method
        }
        
        # Issue (sign) the credential
        signed_vc = _didkit.issue_credential(unsigned_vc, proof_options, private_key_jwk)
        
        # Return the signed credential as a JSON string
        return json.dumps(signed_vc)
        
    except Exception as e:
        logger.error(f"Error signing composite message: {e}")
        raise SigningError(f"Failed to sign composite message: {e}")

def verify(signed_credential_json: str) -> Dict[str, Any]:
    """
    Verify a signed Verifiable Credential.
    
    This function performs both a structural validation against the W3C VC data model
    and cryptographic verification of the credential's signature. It handles both
    JSON-LD and JWT formatted credentials.
    
    Args:
        signed_credential_json: The signed credential as a JSON string
        
    Returns:
        A dictionary containing verification results including 'valid' boolean
    """
    try:
        # Parse credential
        credential = json.loads(signed_credential_json)
        
        # Detect if this is a JWT or JSON-LD format
        is_jwt = False
        if isinstance(signed_credential_json, str) and \
           '.' in signed_credential_json and \
           len(signed_credential_json.split('.')) == 3 and \
           not signed_credential_json.startswith('{'):
            is_jwt = True
            logger.debug("Detected JWT format credential")
        elif isinstance(credential, dict) and 'proof' in credential:
            logger.debug("Detected JSON-LD format credential with proof")
        else:
            logger.warning("Unable to determine credential format, assuming JSON-LD")
        
        # Validate credential structure (for JSON-LD only - JWT structure is hidden in compact form)
        if not is_jwt:
            is_valid_structure, issues = validate_credential_structure(credential)
            if not is_valid_structure:
                logger.warning(f"Credential does not fully comply with W3C structure: {issues}")
                # Continue with verification even if structure has issues
        
        # Determine proof purpose based on credential
        proof_purpose = "assertionMethod"  # Default for credentials
        
        # For JSON-LD credentials, check the proof purpose in the proof
        if not is_jwt and 'proof' in credential:
            proof = credential['proof']
            if isinstance(proof, dict) and 'proofPurpose' in proof:
                proof_purpose = proof['proofPurpose']
                logger.debug(f"Using proof purpose from credential: {proof_purpose}")
        
        # Comprehensive verification options
        verify_options = {
            "proofPurpose": proof_purpose
        }
        
        # Add proofFormat for JWT
        if is_jwt:
            verify_options["proofFormat"] = "jwt"
        
        # Verify the credential
        logger.debug(f"Verifying credential with options: {verify_options}")
        verification_result = _didkit.verify_credential(credential, verify_options)
        
        # Check if verification passed (empty errors array)
        is_valid = verification_result.get("errors", []) == []
        
        # For debugging, log any errors
        if not is_valid and 'errors' in verification_result:
            logger.warning(f"Credential verification failed with errors: {verification_result['errors']}")
        
        # Return a structured result
        result = {
            "valid": is_valid,
            "format": "jwt" if is_jwt else "json-ld",
            "details": verification_result,
            "using_mock": _using_mock
        }
        
        # For JSON-LD, include structure validation results
        if not is_jwt:
            result["structure_valid"] = is_valid_structure
            if not is_valid_structure:
                result["structure_issues"] = issues
                
        return result
        
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing credential JSON: {e}")
        # If JSON parsing failed but it might be a JWT, try as JWT
        if isinstance(signed_credential_json, str) and '.' in signed_credential_json:
            try:
                logger.debug("Trying to verify as raw JWT...")
                verify_options = {
                    "proofPurpose": "assertionMethod",
                    "proofFormat": "jwt"
                }
                verification_result = _didkit.verify_credential(signed_credential_json, verify_options)
                is_valid = verification_result.get("errors", []) == []
                return {
                    "valid": is_valid,
                    "format": "jwt",
                    "details": verification_result,
                    "using_mock": _using_mock
                }
            except Exception as jwt_e:
                logger.error(f"JWT verification also failed: {jwt_e}")
        
        return {
            "valid": False, 
            "error": f"Invalid credential format: {e}",
            "using_mock": _using_mock
        }
    except Exception as e:
        logger.error(f"Error verifying credential: {e}")
        return {
            "valid": False, 
            "error": str(e),
            "using_mock": _using_mock
        }

def extract_message_from_credential(credential_json: str) -> Optional[str]:
    """
    Extract the message from a Verifiable Credential.
    
    Args:
        credential_json: The credential as a JSON string
        
    Returns:
        The message string or None if not found
        
    Raises:
        CredentialParseError: If parsing the credential fails
    """
    try:
        credential = json.loads(credential_json)
        subject = credential.get("credentialSubject", {})
        return subject.get("message")
    except Exception as e:
        logger.error(f"Error extracting message from credential: {e}")
        raise CredentialParseError(f"Error extracting message from credential: {e}")

def extract_composite_from_credential(credential_json: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Extract the resultPointer and codeId from a Verifiable Credential.
    
    Args:
        credential_json: The credential as a JSON string
        
    Returns:
        A tuple of (resultPointer, codeId) or (None, None) if not found
        
    Raises:
        CredentialParseError: If parsing the credential fails
    """
    try:
        credential = json.loads(credential_json)
        subject = credential.get("credentialSubject", {})
        return (subject.get("resultPointer"), subject.get("codeId"))
    except Exception as e:
        logger.error(f"Error extracting composite values from credential: {e}")
        raise CredentialParseError(f"Error extracting composite values from credential: {e}")

def get_subject_did_from_credential(credential_json: str) -> Optional[str]:
    """
    Extract the subject DID from a Verifiable Credential.
    
    Args:
        credential_json: The credential as a JSON string
        
    Returns:
        The subject DID or None if not found
        
    Raises:
        CredentialParseError: If parsing the credential fails
    """
    try:
        credential = json.loads(credential_json)
        subject = credential.get("credentialSubject", {})
        return subject.get("id")
    except Exception as e:
        logger.error(f"Error extracting subject DID from credential: {e}")
        raise CredentialParseError(f"Error extracting subject DID from credential: {e}")

def resolve_did(did: str) -> Dict[str, Any]:
    """
    Resolve a DID to a DID Document.
    
    Args:
        did: The DID to resolve
        
    Returns:
        The DID Document as a dict
        
    Raises:
        DidResolutionError: If resolving the DID fails
    """
    try:
        return _didkit.resolve_did(did)
    except Exception as e:
        logger.error(f"Error resolving DID: {e}")
        raise DidResolutionError(f"Failed to resolve DID: {e}") 