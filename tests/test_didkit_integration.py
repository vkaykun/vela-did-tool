"""
Test the integration with the didkit package.

These tests verify that the core didkit functionality works correctly
through our abstraction layer.
"""

import os
import json
import pytest
import asyncio
from src.did_utils import (
    generate_did,
    sign,
    verify,
    perform_self_test
)

@pytest.mark.asyncio
async def test_generate_did():
    """Test generating a DID."""
    agent_did, verification_method, private_key_jwk = await generate_did()
    
    # Verify we got the expected structure
    assert agent_did.startswith("did:key:")
    assert verification_method.startswith(agent_did + "#")
    assert isinstance(private_key_jwk, dict)
    assert "kty" in private_key_jwk
    assert "crv" in private_key_jwk
    assert "x" in private_key_jwk
    assert "d" in private_key_jwk

@pytest.mark.asyncio
async def test_sign_and_verify():
    """Test signing and verifying a credential."""
    # Generate a DID for testing
    agent_did, verification_method, private_key_jwk = await generate_did()
    
    # Sign a message
    test_message = "Hello, world!"
    signed_credential = await sign(
        issuer_did=agent_did,
        subject_did=agent_did,
        message=test_message,
        private_key_jwk=private_key_jwk
    )
    
    # Verify the structure of the signed credential
    assert signed_credential is not None
    assert isinstance(signed_credential, str)
    
    # Parse and check the credential
    credential = json.loads(signed_credential)
    assert "@context" in credential
    assert "type" in credential
    assert "issuer" in credential
    assert "credentialSubject" in credential
    assert "id" in credential["credentialSubject"]
    assert "message" in credential["credentialSubject"]
    assert credential["credentialSubject"]["message"] == test_message
    assert "proof" in credential
    
    # Verify the credential
    verification_result = await verify(signed_credential)
    
    # Check verification result
    assert verification_result["verified"] is True
    assert len(verification_result["errors"]) == 0

@pytest.mark.asyncio
async def test_self_test():
    """Test that the self-test function succeeds."""
    result = await perform_self_test()
    assert result is True 