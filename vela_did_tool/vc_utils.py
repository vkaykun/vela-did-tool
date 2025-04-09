# vela_did_tool/vc_utils.py 

"""Utilities for Verifiable Credential signing and verification."""

import json
import logging
import datetime
from typing import Dict, Any, Optional, Tuple, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

from jwcrypto import jwk, jws

from pyld import jsonld

import multibase

from .constants import (
    DEFAULT_PROOF_TYPE,
    DEFAULT_PROOF_PURPOSE,
    JSONLD_OPTIONS,
    MULTIBASE_BASE58BTC_PREFIX,
    SECURITY_CONTEXT_V2, 
    VC_JSONLD_CONTEXT_V1
)
from .errors import VcError, SignatureError, NormalizationError, InvalidKeyFormatError, DidError
from .did_utils import get_public_key_bytes_from_did, _b64decode
from .context_loader import default_document_loader

logger = logging.getLogger(__name__)

def _prepare_ld_proof_components(
    credential: Dict[str, Any],
    proof_options: Dict[str, Any]
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Separates proof from credential and prepares proof options."""
    credential_no_proof = credential.copy()
    existing_proof = credential_no_proof.pop("proof", None)
    if existing_proof and "proofValue" in proof_options:
         del proof_options["proofValue"]

    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    proof_config = {
        "type": DEFAULT_PROOF_TYPE,
        "created": now,
        "proofPurpose": DEFAULT_PROOF_PURPOSE,
        **proof_options 
    }
    if "verificationMethod" not in proof_config:
        raise VcError("Missing 'verificationMethod' in proof options for signing.")

    return credential_no_proof, proof_config


def _normalize_and_hash(
    doc: Dict[str, Any],
    document_loader=default_document_loader  
) -> bytes:
    """
    Normalizes a JSON-LD document and returns its SHA-256 hash.
    
    Args:
        doc: The JSON-LD document to normalize
        document_loader: Optional custom document loader. Defaults to the 
                         offline-friendly loader that has common contexts bundled.
                         
    Returns:
        SHA-256 hash of the normalized document as bytes
        
    Raises:
        NormalizationError: If normalization fails
    """
    try:
        normalize_options = {**JSONLD_OPTIONS, 'documentLoader': document_loader}
        
        logger.debug(f"Normalizing document with contexts: {doc.get('@context', [])}")
        normalized_doc = jsonld.normalize(doc, normalize_options)
        
        logger.debug(f"Normalized Document (first 100 chars): {normalized_doc[:100]}")
        hasher = hashes.Hash(hashes.SHA256())
        hasher.update(normalized_doc.encode('utf-8'))
        return hasher.finalize()
    except Exception as e:
        logger.exception(f"JSON-LD normalization failed for document: {doc}")
        raise NormalizationError(f"Failed to normalize document: {e}")


def sign_credential_jsonld(
    credential: Dict[str, Any],
    private_jwk: Dict[str, Any],
    proof_options: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Signs a JSON-LD credential using the Ed25519Signature2020 suite.

    Args:
        credential: The credential document (dict) to sign.
        private_jwk: The private key of the issuer in JWK format (dict).
        proof_options: Dictionary containing proof configuration like
                       'verificationMethod', 'proofPurpose', 'created'.

    Returns:
        The credential dictionary with the 'proof' block added.

    Raises:
        VcError: If signing fails (e.g., normalization, crypto).
        InvalidKeyFormatError: If the JWK is invalid.
    """
    logger.info(f"Signing JSON-LD credential with options: {proof_options}")

    try:
        if 'd' not in private_jwk:
            raise InvalidKeyFormatError("Private JWK must contain 'd' component.")
        priv_key_bytes = _b64decode(private_jwk['d'])
        if len(priv_key_bytes) != 32:
             raise InvalidKeyFormatError("Private key 'd' component has incorrect length for Ed25519.")
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_key_bytes)
    except Exception as e:
        raise InvalidKeyFormatError(f"Failed to load private key from JWK: {e}")
  
    credential_to_normalize, proof_config = _prepare_ld_proof_components(credential, proof_options)

    proof_hash = _normalize_and_hash(proof_config)
    logger.debug(f"Proof config hash: {proof_hash.hex()}")
    doc_hash = _normalize_and_hash(credential_to_normalize)
    logger.debug(f"Credential doc hash: {doc_hash.hex()}")
    data_to_sign = proof_hash + doc_hash
    logger.debug(f"Data to sign (concatenated hashes) length: {len(data_to_sign)}")

    try:
        signature_bytes = private_key.sign(data_to_sign)
        logger.debug(f"Raw signature length: {len(signature_bytes)}") 
    except Exception as e:
        logger.exception("Ed25519 signing operation failed.")
        raise VcError(f"Cryptographic signing failed: {e}")

    proof_value = multibase.encode('base58btc', signature_bytes).decode('ascii')
    logger.debug(f"Encoded proofValue: {proof_value}")

    proof_config_final = proof_config.copy()
    proof_config_final["proofValue"] = proof_value

    signed_credential = credential.copy()
    if '@context' in proof_config_final and SECURITY_CONTEXT_V2 in proof_config_final['@context']:
         proof_config_final['@context'].remove(SECURITY_CONTEXT_V2)
         if not proof_config_final['@context']:
              del proof_config_final['@context']

    signed_credential["proof"] = proof_config_final

    logger.info("Successfully signed JSON-LD credential.")
    return signed_credential


def verify_credential_jsonld(credential: Dict[str, Any]) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Verifies the Ed25519Signature2020 proof on a JSON-LD credential.

    Args:
        credential: The credential dictionary including the 'proof' block.

    Returns:
        A tuple: (verified_status: bool, issuer_did: Optional[str], error_message: Optional[str])
    """
    logger.info("Verifying JSON-LD credential proof.")

    if "proof" not in credential or not isinstance(credential["proof"], dict):
        return False, None, "Credential missing 'proof' block."

    proof = credential["proof"]
    required_proof_fields = ["type", "created", "verificationMethod", "proofPurpose", "proofValue"]
    if not all(field in proof for field in required_proof_fields):
        missing = [f for f in required_proof_fields if f not in proof]
        return False, None, f"Proof block missing required fields: {', '.join(missing)}"

    if proof["type"] != DEFAULT_PROOF_TYPE:
        return False, None, f"Unsupported proof type: {proof['type']}. Expected {DEFAULT_PROOF_TYPE}."

    verification_method_id = proof["verificationMethod"]
    proof_value_encoded = proof["proofValue"]

    try:
        controller_did = verification_method_id.split('#')[0]
        logger.debug(f"Extracting public key for controller DID: {controller_did}")
        
        public_key_bytes = get_public_key_bytes_from_did(controller_did)
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        logger.debug(f"Extracted public key for verification from {controller_did}")

        if not proof_value_encoded.startswith(MULTIBASE_BASE58BTC_PREFIX):
             raise VcError(f"Proof value does not start with expected multibase prefix '{MULTIBASE_BASE58BTC_PREFIX}'.")
        signature_bytes = multibase.decode(proof_value_encoded)
        logger.debug(f"Decoded signature length: {len(signature_bytes)}")

    except Exception as e:
        logger.error(f"Failed to prepare for verification: {e}")
        return False, None, f"Failed to extract key or decode signature: {e}"

    try:
        credential_to_normalize = credential.copy()
        proof_config_to_normalize = credential_to_normalize.pop("proof").copy()
        del proof_config_to_normalize["proofValue"]

        proof_hash = _normalize_and_hash(proof_config_to_normalize)
        logger.debug(f"Verification proof config hash: {proof_hash.hex()}")

        doc_hash = _normalize_and_hash(credential_to_normalize)
        logger.debug(f"Verification credential doc hash: {doc_hash.hex()}")

        data_to_verify = proof_hash + doc_hash
        logger.debug(f"Data to verify (concatenated hashes) length: {len(data_to_verify)}")

        public_key.verify(signature_bytes, data_to_verify)

        logger.info("JSON-LD proof verification successful.")
        issuer_did = controller_did
        return True, issuer_did, None

    except InvalidSignature:
        logger.warning("Signature verification failed: InvalidSignature exception.")
        return False, None, "Invalid signature."
    except NormalizationError as e:
         logger.error(f"Verification failed due to normalization error: {e}")
         return False, None, f"Normalization error during verification: {e.message}"
    except Exception as e:
        logger.exception("An unexpected error occurred during verification.")
        return False, None, f"Verification failed: {e}"

def sign_credential_jwt(
    claims: Dict[str, Any],
    issuer_did: str,
    private_jwk: Dict[str, Any]
) -> str:
    """
    Signs a credential payload as a JWT using JWS with EdDSA.

    Args:
        claims: The payload dictionary (e.g., {"vc": {...}, "iss": ..., "sub": ...}).
                Must include 'iss' matching issuer_did.
        issuer_did: The DID of the issuer (must match 'iss' claim).
        private_jwk: The private key of the issuer in JWK format.

    Returns:
        The compact JWS string.

    Raises:
        VcError: If signing fails.
        InvalidKeyFormatError: If the JWK is invalid.
    """
    logger.info(f"Signing JWT credential for issuer {issuer_did}")

    if "iss" not in claims or claims["iss"] != issuer_did:
        raise VcError(f"JWT claims must include 'iss' field matching the issuer_did '{issuer_did}'.")

    try:
        key = jwk.JWK(**private_jwk)
        if key.key_type != 'OKP' or key['crv'] != 'Ed25519':
             raise InvalidKeyFormatError("JWK must be of type OKP with curve Ed25519.")
    except Exception as e:
        raise InvalidKeyFormatError(f"Failed to load private JWK: {e}")

    try:
        protected_header = {"alg": "EdDSA", "typ": "JWT"}
        jws_token = jws.JWS(json.dumps(claims).encode('utf-8'))
        jws_token.add_signature(key, None, json.dumps(protected_header))
        signed_jwt = jws_token.serialize(compact=True)
        logger.info("Successfully signed JWT credential.")
        return signed_jwt
    except Exception as e:
        logger.exception("JWT signing failed.")
        raise VcError(f"Failed to sign JWT: {e}")


def verify_credential_jwt(jwt_string: str) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]], Optional[str]]:
    """
    Verifies a JWT credential signed with EdDSA.

    Args:
        jwt_string: The compact JWS string.

    Returns:
        Tuple: (verified_status: bool, issuer_did: Optional[str], payload: Optional[dict], error_message: Optional[str])
    """
    logger.info("Verifying JWT credential.")
    try:
        parts = jwt_string.split('.')
        if len(parts) != 3:
            return False, None, None, "Invalid JWT format: must have three parts"
        
        import base64
        def decode_b64url(data):
            padded = data + '=' * (4 - len(data) % 4) if len(data) % 4 else data
            return base64.urlsafe_b64decode(padded.encode('utf-8')).decode('utf-8')
        
        try:
            header = json.loads(decode_b64url(parts[0]))
            payload = json.loads(decode_b64url(parts[1]))
        except Exception as e:
            return False, None, None, f"Invalid JWT format: {e}"
            
        if header.get("alg") != "EdDSA":
            return False, None, None, f"Unsupported JWT algorithm: {header.get('alg')}. Expected EdDSA."
        if "iss" not in payload or not isinstance(payload["iss"], str):
             return False, None, None, "JWT payload missing valid 'iss' (issuer) claim."

        issuer_did = payload["iss"]
        logger.debug(f"JWT issuer identified as: {issuer_did}")

        try:
            public_key_bytes = get_public_key_bytes_from_did(issuer_did)
            
            from base64 import urlsafe_b64encode
            x_b64 = urlsafe_b64encode(public_key_bytes).decode('ascii').rstrip('=')
            pub_jwk = jwk.JWK(kty='OKP', crv='Ed25519', x=x_b64)
    
            jws_token = jws.JWS()
            
            try:
                jws_token.deserialize(jwt_string)
                
                jws_token.verify(pub_jwk)
                
                raw_payload = jws_token.payload
                if not raw_payload:
                    return False, None, None, "Invalid JWT: empty payload after verification"
                    
                logger.info("JWT signature verification successful.")
                return True, issuer_did, payload, None
            except jws.InvalidJWSSignature:
                logger.warning("JWT signature verification failed: InvalidSignature exception.")
                return False, None, None, "Invalid JWT signature: signature verification failed"
            
        except DidError as e:
            logger.error(f"Failed to extract public key from JWT issuer DID: {e}")
            return False, None, None, f"Could not resolve public key for issuer DID: {e.message}"

    except jws.InvalidJWSSignature as e:
        logger.warning(f"JWT signature verification failed: {e}")
        return False, None, None, "Invalid JWT signature."
    except (jws.InvalidJWSObject, json.JSONDecodeError) as e:
         logger.error(f"Invalid JWT format: {e}")
         return False, None, None, f"Invalid JWT format: {e}"
    except Exception as e:
        logger.exception("An unexpected error occurred during JWT verification.")
        return False, None, None, f"JWT verification failed: {e}"