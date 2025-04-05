"""
Tests for the vela-did-tool DID utilities.
"""

import pytest
import json
import sys
import os
import io
import asyncio
from unittest.mock import patch, AsyncMock, MagicMock

# Add src to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.main import main_async
from src.secrets_handler import get_secret_name, NAPTHA_SECRET_PREFIX
import src.did_utils as did_utils

# Test constants
TEST_DID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
TEST_KEY = {
    "kty": "OKP",
    "crv": "Ed25519",
    "d": "q4J-is-pHt-Tj-QJjGUg6amqVCIzuWz-os1SBkh2Jfs",
    "x": "ADQ3jMrIzZR0L6r0CVmcB1IPdpQOeCI8MvFPmZ3ZPBg"
}
TEST_PUBLIC_KEY = {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "ADQ3jMrIzZR0L6r0CVmcB1IPdpQOeCI8MvFPmZ3ZPBg"
}

# Helper function to set up environment for private key
def setup_mock_env_for_did(did):
    secret_name = get_secret_name(did)
    env_var_name = f"{NAPTHA_SECRET_PREFIX}{secret_name}"
    return {env_var_name: json.dumps(TEST_KEY)}

# Test handle_generate
@pytest.mark.asyncio
@patch("src.did_utils.didkit")  # Mock the didkit instance directly
@patch("src.did_utils.perform_self_test", return_value=True)  # Mock the self-test to always pass
async def test_generate_happy_path(mock_self_test, mock_didkit):
    """Test the DID generation with parameters passed directly"""
    # Set up mock responses for didkit methods
    key_jwk_raw = json.dumps(TEST_KEY)
    mock_didkit.generate_ed25519_key.return_value = key_jwk_raw
    mock_didkit.key_to_did.return_value = TEST_DID
    mock_didkit.key_to_verification_method.return_value = f"{TEST_DID}#{TEST_DID.split(':')[-1]}"

    # Run main_async with direct parameter passing and capture the return value
    output = await main_async(
        params={"operation": "generate"}
    )

    # Verify our mocks were called
    mock_didkit.generate_ed25519_key.assert_called_once()
    mock_didkit.key_to_did.assert_called_once()
    mock_didkit.key_to_verification_method.assert_called_once()
    mock_self_test.assert_called_once()

    # Verify output
    assert output["status"] == "success"
    
    # The DID should match the mock's return value
    assert output["agent_did"] == TEST_DID
    assert "private_key_jwk" in output
    assert output["private_key_jwk"] == TEST_KEY
    assert "verification_method" in output
    assert output["verification_method"] == f"{TEST_DID}#{TEST_DID.split(':')[-1]}"
    assert "secret_name" in output
    assert "provisioning_instructions" in output
    
    # Ensure proper instructions are included
    assert "naptha deploy-secrets" in output["provisioning_instructions"]
    assert get_secret_name(TEST_DID) in output["provisioning_instructions"]

# Test handle_sign
@pytest.mark.asyncio
@patch("src.main.sign", autospec=True)  # Use autospec for better mocking
@patch("src.did_utils._resolve_did_and_verification_method")  # Mock the intermediate function
async def test_sign_happy_path(mock_resolve, mock_sign):
    """Test signing with environment variable for key retrieval"""
    # Setup env variables for the secret directly 
    secret_name = get_secret_name(TEST_DID)
    env_var_name = f"{NAPTHA_SECRET_PREFIX}{secret_name}"
    env_vars = {env_var_name: json.dumps(TEST_KEY)}
    
    # Use environment variables directly instead of mocking the function
    with patch.dict(os.environ, env_vars, clear=False):
        mock_resolve.return_value = (TEST_DID, f"{TEST_DID}#{TEST_DID.split(':')[-1]}")
        
        # Mock sign response with a valid JWT signature
        mock_sign.return_value = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ0ZXN0In0.mockSignature"

        # Run with parameters and capture the return value
        output = await main_async(
            params={
                "operation": "sign",
                "agent_did": TEST_DID,
                "message": "HelloWorld",
                "subject_did": "did:key:zSubjectDID",
                "expiration_days": 180
            }
        )

        # Verify mock was called
        assert mock_sign.called
        
        # Verify output
        assert output["status"] == "success"
        assert "signed_credential" in output["result"]

# Test handle_sign with default subject
@pytest.mark.asyncio
@patch("src.main.sign", autospec=True)  # Use autospec for better mocking
@patch("src.did_utils._resolve_did_and_verification_method")  # Mock the intermediate function
async def test_sign_default_subject(mock_resolve, mock_sign):
    """Test signing with default subject (issuer as subject)"""
    # Setup env variables for the secret directly 
    secret_name = get_secret_name(TEST_DID)
    env_var_name = f"{NAPTHA_SECRET_PREFIX}{secret_name}"
    env_vars = {env_var_name: json.dumps(TEST_KEY)}
    
    # Use environment variables directly instead of mocking the function
    with patch.dict(os.environ, env_vars, clear=False):
        mock_resolve.return_value = (TEST_DID, f"{TEST_DID}#{TEST_DID.split(':')[-1]}")
        
        # Mock sign response with a valid JWT signature
        mock_sign.return_value = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ0ZXN0In0.mockSignature"

        # Run with parameters and capture the return value
        output = await main_async(
            params={
                "operation": "sign",
                "agent_did": TEST_DID,
                "message": "HelloWorld"
                # No subject_did or expiration_days
            }
        )

        # Verify mock was called
        assert mock_sign.called
        
        # Verify output
        assert output["status"] == "success"
        assert "signed_credential" in output["result"]

# Test handle_sign_composite
@pytest.mark.asyncio
@patch("src.main.sign_composite", autospec=True)  # Use autospec for better mocking
@patch("src.did_utils._resolve_did_and_verification_method")  # Mock the intermediate function
async def test_sign_composite_happy_path(mock_resolve, mock_sign_composite):
    """Test composite signing with environment variable for key retrieval"""
    # Setup env variables for the secret directly 
    secret_name = get_secret_name(TEST_DID)
    env_var_name = f"{NAPTHA_SECRET_PREFIX}{secret_name}"
    env_vars = {env_var_name: json.dumps(TEST_KEY)}
    
    # Use environment variables directly instead of mocking the function
    with patch.dict(os.environ, env_vars, clear=False):
        mock_resolve.return_value = (TEST_DID, f"{TEST_DID}#{TEST_DID.split(':')[-1]}")
        
        # Mock sign_composite response with a valid JWT signature
        mock_sign_composite.return_value = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ0ZXN0In0.mockSignature"

        # Run with parameters and capture the return value
        output = await main_async(
            params={
                "operation": "sign_composite",
                "agent_did": TEST_DID,
                "result_pointer": "result123",
                "code_id": "code456",
                "subject_did": "did:key:zSubjectDID",
                "expiration_days": 90
            }
        )

        # Verify mock was called
        assert mock_sign_composite.called
        
        # Verify output
        assert output["status"] == "success"
        assert "signed_credential" in output["result"]

# Test handle_verify
@pytest.mark.asyncio
@patch("src.main.verify", autospec=True)  # Use autospec for better mocking
async def test_verify_happy_path(mock_verify):
    """Test verification with parameters passed directly"""
    # Mock verify response with the expected return structure
    mock_verify.return_value = {
        "status": "success",
        "result": {
            "verified": True,
            "issuer": TEST_DID,
            "subject": TEST_DID,
            "message": "HelloWorld",
            "timestamp": "2023-04-01T12:00:00Z",
            "expiration": "2023-10-01T12:00:00Z"
        }
    }

    # Run with parameters and capture the return value
    output = await main_async(
        params={
            "operation": "verify",
            "signed_credential": "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ0ZXN0In0.mockSignature",
            "expected_message": "HelloWorld",
            "expected_subject": TEST_DID
        }
    )

    # Verify our mock was called
    mock_verify.assert_called_once()
    
    # Verify output structure
    assert output["status"] == "success"
    assert "result" in output
    assert output["result"]["verified"] == True
    assert output["result"]["message"] == "HelloWorld"
    assert output["result"]["issuer"] == TEST_DID
    assert output["result"]["subject"] == TEST_DID

# Test error handling
@pytest.mark.asyncio
@patch("src.main.parse_input_parameters")
async def test_missing_operation(mock_parse_params):
    """Test error handling for missing operation parameter"""
    # Return an empty dict to simulate missing operation
    mock_parse_params.return_value = {}
    
    # Run without an operation parameter
    output = await main_async()
    
    # Verify the error response
    assert output["status"] == "error"
    assert "error" in output
    assert "required parameter" in output["error"]

# Test input validation for sign
@pytest.mark.asyncio
async def test_sign_missing_params():
    """Test error handling for missing parameters in sign operation"""
    # Run with missing agent_did
    output = await main_async(
        params={
            "operation": "sign",
            # Missing agent_did
            "message": "test"
        }
    )
    
    # Verify error response
    assert output["status"] == "error"
    assert "error" in output
    assert "agent-did" in output["error"].lower() or "agent_did" in output["error"].lower()

@pytest.mark.asyncio
@patch("src.did_utils.sign")
async def test_sign_missing_secret(mock_sign):
    """Test error handling when secret key is not found"""
    # Empty environment (no secrets)
    with patch.dict(os.environ, {}, clear=True):
        # Mock the error that would occur when key is not found
        mock_sign.side_effect = KeyError(f"Key not found: {NAPTHA_SECRET_PREFIX}test_secret")
        
        # Run with parameters
        output = await main_async(
            params={
                "operation": "sign",
                "agent_did": TEST_DID,
                "message": "HelloWorld"
            }
        )
        
        # Verify error response
        assert output["status"] == "error"
        assert "error" in output
        assert "key not found" in output["error"].lower() or "private key" in output["error"].lower()

# Test stdin-based parameter parsing
@pytest.mark.asyncio
@patch("src.main.parse_input_parameters")
@patch("src.did_utils.didkit")  # Mock the didkit instance directly
@patch("src.did_utils.perform_self_test", return_value=True)  # Mock the self-test to always pass
async def test_parameters_from_stdin(mock_self_test, mock_didkit, mock_parse_params):
    """Test parameter ingestion from stdin"""
    # Set up our mock responses
    key_jwk_raw = json.dumps(TEST_KEY)
    mock_didkit.generate_ed25519_key.return_value = key_jwk_raw
    mock_didkit.key_to_did.return_value = TEST_DID
    mock_didkit.key_to_verification_method.return_value = f"{TEST_DID}#{TEST_DID.split(':')[-1]}"
    
    # Setup parameters that would normally come from stdin
    stdin_params = {
        "operation": "generate"
    }
    mock_parse_params.return_value = stdin_params
    
    # Call main_async with no parameters, forcing it to use stdin
    output = await main_async()
    
    # Verify our mocks were called
    mock_didkit.generate_ed25519_key.assert_called_once()
    mock_parse_params.assert_called_once()
    mock_self_test.assert_called_once()
    
    # Verify the output is correct
    assert output["status"] == "success"
    assert output["agent_did"] == TEST_DID
    assert "private_key_jwk" in output
    assert output["private_key_jwk"] == TEST_KEY

# Test complete end-to-end flow
@pytest.mark.asyncio
@patch("src.did_utils.didkit")  # Mock the didkit instance directly
@patch("src.main.sign", autospec=True)
@patch("src.main.verify", autospec=True)
@patch("src.did_utils._resolve_did_and_verification_method")
@patch("src.did_utils.perform_self_test", return_value=True)  # Mock the self-test to always pass
async def test_e2e_workflow(mock_self_test, mock_resolve, mock_verify, mock_sign, mock_didkit):
    """Test a complete workflow: generate -> sign -> verify"""
    # 1. Setup
    key_jwk_raw = json.dumps(TEST_KEY)
    mock_didkit.generate_ed25519_key.return_value = key_jwk_raw
    mock_didkit.key_to_did.return_value = TEST_DID
    mock_didkit.key_to_verification_method.return_value = f"{TEST_DID}#{TEST_DID.split(':')[-1]}"
    
    # 2. Generate DID and capture output
    generate_output = await main_async(
        params={"operation": "generate"}
    )
    
    # Verify generate output and our mock was called
    assert generate_output["status"] == "success"
    assert generate_output["agent_did"] == TEST_DID
    assert "private_key_jwk" in generate_output
    mock_self_test.assert_called_once()
    
    # 3. Setup for sign with environment variable
    secret_name = get_secret_name(TEST_DID)
    env_var_name = f"{NAPTHA_SECRET_PREFIX}{secret_name}"
    env_vars = {env_var_name: json.dumps(TEST_KEY)}
    
    # Mock the resolution function
    mock_resolve.return_value = (TEST_DID, f"{TEST_DID}#{TEST_DID.split(':')[-1]}")
    
    # Mock the sign function with a valid JWT credential
    jwt_credential = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ0ZXN0In0.mockSignature"
    mock_sign.return_value = jwt_credential
    
    # 4. Sign a message
    with patch.dict(os.environ, env_vars, clear=False):
        sign_output = await main_async(
            params={
                "operation": "sign",
                "agent_did": TEST_DID,
                "message": "HelloWorld"
            }
        )
        
    # Verify sign output
    assert sign_output["status"] == "success"
    assert "result" in sign_output
    assert "signed_credential" in sign_output["result"]
    assert sign_output["result"]["signed_credential"] == jwt_credential
    
    # 5. Setup for verify
    verify_result = {
        "verified": True,
        "issuer": TEST_DID,
        "subject": TEST_DID,
        "message": "HelloWorld"
    }
    mock_verify.return_value = {
        "status": "success",
        "result": verify_result
    }
    
    # 6. Verify the credential
    verify_output = await main_async(
        params={
            "operation": "verify",
            "signed_credential": jwt_credential,
            "expected_message": "HelloWorld"
        }
    )
    
    # Verify verification output
    assert verify_output["status"] == "success"
    assert "result" in verify_output
    assert verify_output["result"]["verified"] == True
    assert verify_output["result"]["issuer"] == TEST_DID
    assert verify_output["result"]["message"] == "HelloWorld" 