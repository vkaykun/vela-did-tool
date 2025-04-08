# vela_did_tool/schemas.py
"""Pydantic models for input validation and output structuring."""

from typing import Dict, Any, Optional, Literal, Union
from pydantic import BaseModel, Field

class InputSchema(BaseModel):
    func_name: Literal["generate", "generate-did", "resolve", "resolve-did", "sign", "verify"]
    
    func_input_data: Dict[str, Any] = Field(default_factory=dict)

class VerificationMethod(BaseModel):
    """Represents a DID Document Verification Method entry."""
    id: str
    type: str
    controller: str
    publicKeyMultibase: str

class GenerateOutput(BaseModel):
    """Output data for the 'generate' function."""
    did: str = Field(..., description="The generated did:key string.")
    publicKey: Dict[str, Any] = Field(..., description="Public key information.")
    privateKey: Dict[str, Any] = Field(..., description="The private key in JWK format (includes public parts). Handle with care.")

class SignOutput(BaseModel):
    """Output data for the 'sign' function."""
    signed_credential: Optional[Dict[str, Any]] = Field(None, description="The signed Verifiable Credential in JSON-LD format (if format was 'jsonld').")
    signed_jwt: Optional[str] = Field(None, description="The signed Verifiable Credential as a compact JWS string (if format was 'jwt').")

class VerifyOutput(BaseModel):
    """Output data for the 'verify' function."""
    verified: bool = Field(..., description="True if the credential signature is valid, False otherwise.")
    issuer: Optional[str] = Field(None, description="The DID of the issuer extracted from the credential/JWT (if verification succeeded).")
    payload: Optional[Dict[str, Any]] = Field(None, description="The decoded payload of the JWT (if applicable and verification succeeded).")
    error: Optional[str] = Field(None, description="Reason for verification failure, if applicable.")

class ErrorOutput(BaseModel):
    """Standardized error output format."""
    error: str = Field(..., description="A short error code or category.")
    message: str = Field(..., description="A human-readable description of the error.")

class Proof(BaseModel):
    """Model for a Linked Data Proof structure (subset)."""
    type: str
    created: str
    verificationMethod: str
    proofPurpose: str
    proofValue: Optional[str] = None  