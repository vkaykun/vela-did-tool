# vela_did_tool/constants.py
"""Shared constants for the vela-did-tool."""

import sys

NAPTHA_SECRET_PREFIX: str = "NAPTHA_SECRET_"

DID_KEY_PREFIX: str = "did:key:"
SUPPORTED_DID_METHOD: str = "key"
SUPPORTED_KEY_TYPE: str = "Ed25519"

ED25519_PUB_MULTICODEC_CODE: int = 0xed
ED25519_PUB_MULTICODEC_PREFIX_BYTES: bytes = b'\xed\x01'
MULTICODEC_ED25519_PUB_HEADER = b'\xed\x01'
MULTIBASE_BASE58BTC_PREFIX: str = "z"

DEFAULT_PROOF_TYPE: str = "Ed25519Signature2020"
DEFAULT_PROOF_PURPOSE: str = "assertionMethod"
VC_JSONLD_CONTEXT_V1: str = "https://www.w3.org/2018/credentials/v1"
SECURITY_CONTEXT_V2: str = "https://w3id.org/security/suites/ed25519-2020/v1"

JSONLD_OPTIONS = {
    "algorithm": "URDNA2015",
    "format": "application/n-quads"
}

STDIN = sys.stdin
STDOUT = sys.stdout
STDERR = sys.stderr

EXIT_SUCCESS = 0
EXIT_FAILURE = 1