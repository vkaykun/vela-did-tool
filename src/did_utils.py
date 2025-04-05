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
import uuid
import asyncio
import traceback
from typing import Dict, Optional, Any, Tuple, List, Union

# Import the production guard
from .production_guard import PRODUCTION_MODE, fail_in_production

# Import custom error types
from .exceptions import (
    CredentialError, 
    DidGenerationError, 
    SigningError, 
    VerificationError,
    CredentialParseError,
    CredentialFormatError,
    DidResolutionError,
    ProductionGuardError,
    SelfTestError
)

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("vela-did-tool.did_utils")

# Days until credential expiration (default 90 days)
DEFAULT_EXPIRATION_DAYS = int(os.environ.get("VELA_CREDENTIAL_EXPIRATION_DAYS", "90"))

# Custom credential types
MACHINE_CREDENTIAL_TYPE = "MachineCredential"
AGENT_CREDENTIAL_TYPE = "AgentCredential"

# Default credential types to use
DEFAULT_CREDENTIAL_TYPES = ["VerifiableCredential", MACHINE_CREDENTIAL_TYPE, AGENT_CREDENTIAL_TYPE]

# Default contexts to include
DEFAULT_CONTEXTS = [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
]

# Import didkit
try:
    import didkit
    logger.info(f"DIDKit library loaded successfully, version: {didkit.getVersion() if hasattr(didkit, 'getVersion') else 'unknown'}")
except (ImportError, OSError) as e:
    # In production mode, fail loudly
    if PRODUCTION_MODE:
        logger.critical(f"Failed to import didkit in production mode: {e}")
        fail_in_production(f"DIDKit library import failed: {e}")
    else:
        # In development mode, still fail but with a warning
        logger.error(f"Failed to import didkit: {e}")
        logger.error("DIDKit is required for all cryptographic operations")
        raise ImportError(f"Failed to import didkit. Please ensure it is installed correctly: {e}")

async def perform_self_test() -> bool:
    """
    Perform a self-test of the DIDKit functionality to ensure it works correctly.
    
    Returns:
        True if the test passed, False otherwise
    """
    try:
        # Simple self-test: Generate a key, issue a credential, verify it
        logger.info("Performing DIDKit self-test...")
        
        # Generate a key
        logger.debug("Generating Ed25519 key")
        key_str = didkit.generateEd25519Key()
        logger.debug(f"Generated key: {key_str[:25]}...")
        
        logger.debug("Converting key to DID")
        did = didkit.keyToDID("key", key_str)
        logger.debug(f"DID: {did}")
        
        verification_method = didkit.keyToVerificationMethod("key", key_str)
        logger.debug(f"Verification method: {verification_method}")
        
        # Simplify the credential to minimal required fields
        logger.debug("Creating credential")
        credential = {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential"],
            "issuer": did,
            "issuanceDate": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "credentialSubject": {
                "id": did,
                "message": "DIDKit Self-Test"
            }
        }
        
        credential_json = json.dumps(credential)
        logger.debug(f"Credential JSON: {credential_json[:100]}...")
        
        proof_options = {
            "verificationMethod": verification_method,
            "proofPurpose": "assertionMethod"
        }
        proof_options_json = json.dumps(proof_options)
        logger.debug(f"Proof options: {proof_options_json}")
        
        logger.debug("Issuing credential")
        signed = didkit.issueCredential(
            credential_json,
            proof_options_json,
            key_str
        )
        logger.debug(f"Signed credential: {signed[:100]}...")
        
        logger.debug("Verifying credential")
        verify_options = {
            "proofPurpose": "assertionMethod"
        }
        verify_options_json = json.dumps(verify_options)
        verify_result = didkit.verifyCredential(signed, verify_options_json)
        logger.debug(f"Verification result: {verify_result}")
        
        # Check if verification succeeded
        verify_result_obj = json.loads(verify_result)
        if "errors" in verify_result_obj and len(verify_result_obj["errors"]) > 0:
            error_msg = "; ".join(verify_result_obj["errors"])
            raise Exception(f"Credential verification failed: {error_msg}")
        
        logger.info("DIDKit self-test passed")
        return True
    except Exception as e:
        error_message = str(e)
        logger.error(f"DIDKit self-test failed: {error_message}")
        logger.error(f"Exception type: {type(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        
        if PRODUCTION_MODE:
            raise SelfTestError(f"DIDKit self-test failed: {str(e)}")
        
        return False

async def generate_did() -> Tuple[str, str, Dict[str, Any]]:
    """
    Generate a new DID with an Ed25519 key pair.
    
    Returns:
        Tuple of (DID string, verification method URL, private key JWK dict)
    
    Raises:
        DidGenerationError: If DID generation fails
    """
    try:
        # Generate a new Ed25519 key
        key_str = didkit.generateEd25519Key()
        key = json.loads(key_str)
        
        # Convert to a DID and verification method
        did = didkit.keyToDID("key", key_str)
        verification_method = didkit.keyToVerificationMethod("key", key_str)
        
        return did, verification_method, key
    except Exception as e:
        logger.error(f"Error generating DID: {e}")
        raise DidGenerationError(f"Failed to generate DID: {e}")

async def sign(
    issuer_did: str,
    subject_did: str,
    message: str,
    private_key_jwk: Dict[str, Any],
    types: List[str] = None,
    contexts: List[str] = None,
    expiration_days: Optional[int] = None
) -> str:
    """
    Sign a message using the provided private key.
    
    Args:
        issuer_did: The DID of the issuer
        subject_did: The DID of the subject
        message: The message to sign
        private_key_jwk: The private key as a JWK dict
        types: Optional list of credential types
        contexts: Optional list of contexts
        expiration_days: Optional number of days until expiration
    
    Returns:
        The signed credential as a JSON string
    
    Raises:
        SigningError: If signing fails
    """
    try:
        # Use default values if not provided
        if types is None:
            types = DEFAULT_CREDENTIAL_TYPES
        if contexts is None:
            contexts = DEFAULT_CONTEXTS
        
        # Create the credential
        credential = create_credential_json(
            issuer_did=issuer_did,
            subject_did=subject_did,
            message=message,
            expiration_days=expiration_days
        )
        
        # Add the types and contexts
        credential["type"] = types
        credential["@context"] = contexts
        
        # Get verification method from the private key
        key_str = json.dumps(private_key_jwk)
        verification_method = didkit.keyToVerificationMethod("key", key_str)
        
        # Create the proof options
        proof_options = {
            "verificationMethod": verification_method,
            "proofPurpose": "assertionMethod"
        }
        
        # Sign the credential
        signed_credential = didkit.issueCredential(
            json.dumps(credential),
            json.dumps(proof_options),
            key_str
        )
        
        return signed_credential
    except Exception as e:
        logger.error(f"Error signing message: {e}")
        raise SigningError(f"Failed to sign message: {e}")

async def sign_composite(
    issuer_did: str,
    subject_did: str,
    message_fields: Dict[str, Any],
    private_key_jwk: Dict[str, Any],
    types: List[str] = None,
    contexts: List[str] = None,
    expiration_days: Optional[int] = None
) -> str:
    """
    Sign a composite message (multiple fields) using the provided private key.
    
    Args:
        issuer_did: The DID of the issuer
        subject_did: The DID of the subject
        message_fields: Dictionary of message fields to include in the credential
        private_key_jwk: The private key as a JWK dict
        types: Optional list of credential types
        contexts: Optional list of contexts
        expiration_days: Optional number of days until expiration
    
    Returns:
        The signed credential as a JSON string
    
    Raises:
        SigningError: If signing fails
    """
    try:
        # Use default values if not provided
        if types is None:
            types = DEFAULT_CREDENTIAL_TYPES
        if contexts is None:
            contexts = DEFAULT_CONTEXTS
        
        # Create the credential
        credential = create_composite_credential_json(
            issuer_did=issuer_did,
            subject_did=subject_did,
            message_fields=message_fields,
            expiration_days=expiration_days
        )
        
        # Add the types and contexts
        credential["type"] = types
        credential["@context"] = contexts
        
        # Get verification method from the private key
        key_str = json.dumps(private_key_jwk)
        verification_method = didkit.keyToVerificationMethod("key", key_str)
        
        # Create the proof options
        proof_options = {
            "verificationMethod": verification_method,
            "proofPurpose": "assertionMethod"
        }
        
        # Sign the credential
        signed_credential = didkit.issueCredential(
            json.dumps(credential),
            json.dumps(proof_options),
            key_str
        )
        
        return signed_credential
    except Exception as e:
        logger.error(f"Error signing composite message: {e}")
        raise SigningError(f"Failed to sign composite message: {e}")

async def verify(signed_credential: str) -> Dict[str, Any]:
    """
    Verify a signed credential.
    
    Args:
        signed_credential: The signed credential as a JSON string
        
    Returns:
        A dictionary with verification results
        
    Raises:
        VerificationError: If verification fails
    """
    try:
        # Create the verification options
        verify_options = {
            "proofPurpose": "assertionMethod"
        }
        
        # Verify the credential
        verify_result = didkit.verifyCredential(
            signed_credential,
            json.dumps(verify_options)
        )
        
        # Parse the verification result
        result = json.loads(verify_result)
        
        # Check if there are any errors
        if "errors" in result and len(result["errors"]) > 0:
            logger.error(f"Verification errors: {result['errors']}")
            result["valid"] = False
        else:
            result["valid"] = True
        
        return result
    except Exception as e:
        logger.error(f"Error verifying credential: {e}")
        raise VerificationError(f"Failed to verify credential: {e}")

def create_credential_json(
    issuer_did: str,
    subject_did: str,
    message: Optional[str] = None,
    result_pointer: Optional[str] = None,
    code_id: Optional[str] = None,
    expiration_days: Optional[int] = None
) -> Dict[str, Any]:
    """
    Create a credential JSON with the specified attributes.
    
    Args:
        issuer_did: DID of the issuer
        subject_did: DID of the subject
        message: Optional message to include
        result_pointer: Optional result pointer to include
        code_id: Optional code ID to include
        expiration_days: Optional number of days until expiration
    
    Returns:
        Credential JSON as a dict
    """
    # Determine the expiration date if specified
    issuance_date = datetime.datetime.now(datetime.timezone.utc)
    expiration_date = None
    
    if expiration_days is not None and expiration_days > 0:
        expiration_date = issuance_date + datetime.timedelta(days=expiration_days)
    elif DEFAULT_EXPIRATION_DAYS > 0:
        expiration_date = issuance_date + datetime.timedelta(days=DEFAULT_EXPIRATION_DAYS)
    
    # Create credential JSON
    credential = {
        "@context": DEFAULT_CONTEXTS,
        "id": f"urn:uuid:{str(uuid.uuid4())}",
        "type": DEFAULT_CREDENTIAL_TYPES,
        "issuer": issuer_did,
        "issuanceDate": issuance_date.isoformat().replace('+00:00', 'Z'),
        "credentialSubject": {
            "id": subject_did
        }
    }
    
    # Add expiration date if set
    if expiration_date is not None:
        credential["expirationDate"] = expiration_date.isoformat().replace('+00:00', 'Z')
    
    # Add optional fields to credentialSubject
    if message is not None:
        credential["credentialSubject"]["message"] = message
    
    if result_pointer is not None:
        credential["credentialSubject"]["resultPointer"] = result_pointer
    
    if code_id is not None:
        credential["credentialSubject"]["codeId"] = code_id
    
    return credential

def extract_message_from_credential(signed_credential: str) -> str:
    """
    Extract the message from a signed credential.
    
    Args:
        signed_credential: The signed credential as a JSON string
    
    Returns:
        The message from the credential
    
    Raises:
        CredentialParseError: If parsing the credential fails
        CredentialFormatError: If the credential doesn't contain a message
    """
    try:
        # Parse the credential
        credential = json.loads(signed_credential)
        
        # Extract the message
        if "credentialSubject" in credential and "message" in credential["credentialSubject"]:
            return credential["credentialSubject"]["message"]
        else:
            raise CredentialFormatError("Credential doesn't contain a message")
    except json.JSONDecodeError:
        raise CredentialParseError("Failed to parse credential JSON")

def extract_composite_from_credential(signed_credential: str) -> Dict[str, Any]:
    """
    Extract composite data from a signed credential.
    
    Args:
        signed_credential: The signed credential as a JSON string
    
    Returns:
        Dictionary with composite data fields
    
    Raises:
        CredentialParseError: If parsing the credential fails
        CredentialFormatError: If the credential doesn't contain composite data
    """
    try:
        # Parse the credential
        credential = json.loads(signed_credential)
        
        # Extract the composite data
        if "credentialSubject" in credential:
            subject = credential["credentialSubject"]
            composite = {}
            
            # Check for expected composite fields
            if "resultPointer" in subject:
                composite["resultPointer"] = subject["resultPointer"]
            if "codeId" in subject:
                composite["codeId"] = subject["codeId"]
            
            if composite:
                return composite
        
        raise CredentialFormatError("Credential doesn't contain composite data")
    except json.JSONDecodeError:
        raise CredentialParseError("Failed to parse credential JSON")

def get_subject_did_from_credential(signed_credential: str) -> str:
    """
    Extract the subject DID from a signed credential.
    
    Args:
        signed_credential: The signed credential as a JSON string
    
    Returns:
        The subject DID
    
    Raises:
        CredentialParseError: If parsing the credential fails
        CredentialFormatError: If the credential doesn't contain a subject DID
    """
    try:
        # Parse the credential
        credential = json.loads(signed_credential)
        
        # Extract the subject DID
        if "credentialSubject" in credential and "id" in credential["credentialSubject"]:
            return credential["credentialSubject"]["id"]
        else:
            raise CredentialFormatError("Credential doesn't contain a subject DID")
    except json.JSONDecodeError:
        raise CredentialParseError("Failed to parse credential JSON")

# Perform self-test in production mode
if PRODUCTION_MODE:
    try:
        asyncio.run(perform_self_test())
    except Exception as e:
        logger.critical(f"DIDKit self-test failed in production mode: {e}")
        fail_in_production(f"DIDKit self-test failed: {e}") 