# vela_did_tool/did_utils.py
"""Utilities for DID:Key generation, parsing, and key retrieval."""

import os
import json
import logging
import base64
from typing import Dict, Any, Tuple

from jwcrypto import jwk
import multibase
import multicodec

from .constants import (
    NAPTHA_SECRET_PREFIX,
    DID_KEY_PREFIX,
    MULTICODEC_ED25519_PUB_HEADER,
    MULTIBASE_BASE58BTC_PREFIX,
    DEFAULT_PROOF_TYPE,
    SUPPORTED_KEY_TYPE
)
from .errors import DidError, KeyNotFoundError, InvalidKeyFormatError, ConfigurationError
from .schemas import VerificationMethod

logger = logging.getLogger(__name__)

def _b64decode(data):
    """Base64url decoding function to replace jwk.JWK._b64decode"""
    padded = data + '=' * (4 - len(data) % 4) if len(data) % 4 else data
    standard = padded.replace('-', '+').replace('_', '/')
    return base64.b64decode(standard)

def sanitize_did_for_env(did: str) -> str:
    """
    Sanitizes a DID string to create a valid environment variable name.
    Rule: Replaces ':' and '.' with '_'.
    Example: did:key:z6Mkp... -> did_key_z6Mkp...
    """
    if not isinstance(did, str):
        raise TypeError("DID must be a string")
    return did.replace(":", "_").replace(".", "_")

def get_private_jwk_from_env(agent_did: str) -> Dict[str, Any]:
    """
    Retrieves the private key (in JWK JSON format) for a given DID
    from an environment variable.

    Args:
        agent_did: The DID whose private key is needed.

    Returns:
        The parsed private JWK dictionary.

    Raises:
        KeyNotFoundError: If the environment variable is not set.
        InvalidKeyFormatError: If the environment variable content is not valid JSON
                                or doesn't represent a valid JWK.
        ConfigurationError: If the environment variable name cannot be constructed.
    """
    try:
        sanitized_did = sanitize_did_for_env(agent_did)
        env_var_name = f"{NAPTHA_SECRET_PREFIX}{sanitized_did}"
        logger.info(f"Attempting to retrieve secret from env var: {env_var_name}")
    except Exception as e:
        raise ConfigurationError(f"Failed to construct environment variable name for DID {agent_did}: {e}")

    jwk_str = os.getenv(env_var_name)
    if jwk_str is None:
        raise KeyNotFoundError(f"Secret environment variable '{env_var_name}' not found for DID '{agent_did}'.")

    try:
        private_jwk = json.loads(jwk_str)
        if not isinstance(private_jwk, dict) or "kty" not in private_jwk or "crv" not in private_jwk or "d" not in private_jwk:
             raise InvalidKeyFormatError(f"Value in '{env_var_name}' is not a valid private JWK dictionary.")
        logger.info(f"Successfully retrieved and parsed JWK from {env_var_name}")
        logger.info(f"Successfully retrieved and parsed JWK from {env_var_name}")
        return private_jwk
    except json.JSONDecodeError:
        raise InvalidKeyFormatError(f"Failed to parse JSON from environment variable '{env_var_name}'.")
    except Exception as e:
         raise InvalidKeyFormatError(f"Content of '{env_var_name}' is not a valid JWK: {e}")


def generate_did_key_ed25519() -> Tuple[str, VerificationMethod, Dict[str, Any]]:
    """
    Generates a new Ed25519 key pair and constructs the corresponding
    did:key identifier, verification method, and private JWK.

    Returns:
        A tuple containing:
        - The generated did:key string.
        - The VerificationMethod object.
        - The private key in JWK format (dict).

    Raises:
        DidError: If key generation or DID formatting fails.
    """
    try:
        key = jwk.JWK.generate(kty='OKP', crv='Ed25519')
        private_jwk = json.loads(key.export_private())
        public_jwk = json.loads(key.export_public())  

        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        if 'x' not in public_jwk:
             raise DidError("Generated public JWK missing 'x' component.")
        pub_bytes_b64url = public_jwk['x']
        pub_bytes = _b64decode(pub_bytes_b64url)
        if len(pub_bytes) != 32:
             raise DidError(f"Extracted public key has incorrect length: {len(pub_bytes)} bytes (expected 32).")

        multicodec_pub_bytes = MULTICODEC_ED25519_PUB_HEADER + pub_bytes

        public_key_multibase = multibase.encode('base58btc', multicodec_pub_bytes).decode('ascii')

        did = f"{DID_KEY_PREFIX}{public_key_multibase}"

        vm_id = f"{did}#{public_key_multibase}"
        verification_method = VerificationMethod(
            id=vm_id,
            type="Ed25519VerificationKey2020",
            controller=did,
            publicKeyMultibase=public_key_multibase
        )

        logger.info(f"Generated new did:key: {did}")
        return did, verification_method, private_jwk

    except Exception as e:
        logger.exception("Failed to generate did:key")
        raise DidError(f"Error during did:key generation: {e}")


def get_public_key_bytes_from_did(did: str) -> bytes:
    """
    Extracts the raw Ed25519 public key bytes from a did:key string.

    Args:
        did: The did:key string (e.g., "did:key:z6Mkp...")

    Returns:
        The raw 32-byte Ed25519 public key.

    Raises:
        DidError: If the DID format is invalid, multibase/multicodec decoding fails,
                  or the key type is not supported Ed25519.
    """
    if not did.startswith(DID_KEY_PREFIX):
        raise DidError(f"Invalid DID format: Must start with '{DID_KEY_PREFIX}'.")

    multibase_key = did[len(DID_KEY_PREFIX):]

    if not multibase_key.startswith(MULTIBASE_BASE58BTC_PREFIX):
         raise DidError(f"Unsupported multibase encoding: Expected prefix '{MULTIBASE_BASE58BTC_PREFIX}'.")

    try:
        multicodec_bytes = multibase.decode(multibase_key)
    except Exception as e:
        raise DidError(f"Failed to decode multibase key '{multibase_key}': {e}")

    if not multicodec_bytes.startswith(MULTICODEC_ED25519_PUB_HEADER):
        expected_prefix_hex = MULTICODEC_ED25519_PUB_HEADER.hex()
        actual_prefix_hex = multicodec_bytes[:len(MULTICODEC_ED25519_PUB_HEADER)].hex()
        raise DidError(f"Unsupported key type: Expected multicodec prefix {expected_prefix_hex} (Ed25519 Public Key), got {actual_prefix_hex}.")

    public_key_bytes = multicodec_bytes[len(MULTICODEC_ED25519_PUB_HEADER):]

    if len(public_key_bytes) != 32:
        raise DidError(f"Decoded public key has incorrect length: {len(public_key_bytes)} bytes (expected 32).")

    logger.debug(f"Extracted public key bytes from DID {did}")
    return public_key_bytes

def resolve_did(did: str) -> Dict[str, Any]:
    """
    Resolves a DID to its DID Document.
    Currently only supports did:key method.

    Args:
        did: The DID to resolve (e.g., did:key:z6Mk...)

    Returns:
        The DID Document as a dictionary.

    Raises:
        DidError: If resolution fails or the DID method is not supported.
    """
    if not did.startswith(DID_KEY_PREFIX):
        raise DidError(f"Unsupported DID method. Only {DID_KEY_PREFIX} is currently supported.")
    
    try:
        public_key_bytes = get_public_key_bytes_from_did(did)
        
        multibase_key = did[len(DID_KEY_PREFIX):]
        
        did_document = {
            "@context": "https://www.w3.org/ns/did/v1",
            "id": did,
            "verificationMethod": [
                {
                    "id": f"{did}#{multibase_key}",
                    "type": "Ed25519VerificationKey2020",
                    "controller": did,
                    "publicKeyMultibase": multibase_key
                }
            ],
            "authentication": [
                f"{did}#{multibase_key}"
            ],
            "assertionMethod": [
                f"{did}#{multibase_key}"
            ]
        }
        
        logger.info(f"Resolved DID: {did}")
        return did_document
        
    except Exception as e:
        logger.exception(f"Failed to resolve DID: {did}")
        raise DidError(f"Error resolving DID: {e}")