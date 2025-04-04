"""
Tests for the vela-did-tool DID utilities.
"""

import pytest
import json
from unittest.mock import patch, AsyncMock, MagicMock

import sys
import os

# Add src to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.main import main_async
from src.secrets_handler import get_secret_name
import src.did_utils as did_utils

# Test get_secret_name utility
def test_get_secret_name():
    """Test that the get_secret_name function formats DIDs correctly"""
    did = "did:key:z123456789"
    expected = "vela_agent_private_key_did_key_z123456789"
    assert get_secret_name(did) == expected

# Test handle_generate
@pytest.mark.asyncio
@patch("os.getenv")
@patch("src.main.store_agent_private_key", new_callable=AsyncMock)
@patch("src.did_utils.generate_did")
async def test_generate_happy_path(mock_gen, mock_store, mock_getenv, capsys):
    """Test the DID generation happy path"""
    # 1. Mock environment: operation='generate'
    def getenv_side_effect(key, default=None):
        if key == "INPUT_OPERATION":
            return "generate"
        return default
    mock_getenv.side_effect = getenv_side_effect

    # 2. Mock did_utils.generate_did
    mock_gen.return_value = {
        "did": "did:key:zTestDID123",
        "privateKeyJwk": {"kty":"OKP","d":"secret"},
        "publicKeyJwk": {"kty":"OKP","x":"public"}
    }

    # 3. Mock store_agent_private_key
    mock_store.return_value = True

    # 4. Run main_async
    await main_async()

    # 5. Capture stdout
    captured = capsys.readouterr()
    output = json.loads(captured.out.strip())
    assert output["status"] == "success"
    assert output["did"] == "did:key:zTestDID123"
    assert "publicKeyJwk" in output

# Test handle_sign
@pytest.mark.asyncio
@patch("os.getenv")
@patch("src.main.retrieve_agent_private_key", new_callable=AsyncMock)
@patch("src.did_utils.sign")
async def test_sign_happy_path(mock_sign, mock_retrieve, mock_getenv, capsys):
    """Test the signing happy path"""
    def getenv_side_effect(key, default=None):
        env_map = {
            "INPUT_OPERATION": "sign",
            "INPUT_AGENT_DID": "did:key:zTestDID",
            "INPUT_MESSAGE": "HelloWorld",
            "INPUT_SUBJECT_DID": "did:key:zSubjectDID",
            "INPUT_EXPIRATION_DAYS": "180"
        }
        return env_map.get(key, default)
    mock_getenv.side_effect = getenv_side_effect

    # Mock retrieve key
    mock_retrieve.return_value = {"kty":"OKP","d":"secret"}
    # Mock sign
    mock_sign.return_value = "mock_signature"

    await main_async()
    captured = capsys.readouterr()
    output = json.loads(captured.out.strip())
    assert output["status"] == "success"
    assert output["signature"] == "mock_signature"
    # Verify sign was called with correct params
    mock_sign.assert_called_once_with(
        message="HelloWorld", 
        private_key_jwk={"kty":"OKP","d":"secret"}, 
        issuer_did="did:key:zTestDID",
        subject_did="did:key:zSubjectDID",
        expiration_days=180
    )

# Test handle_sign with default subject
@pytest.mark.asyncio
@patch("os.getenv")
@patch("src.main.retrieve_agent_private_key", new_callable=AsyncMock)
@patch("src.did_utils.sign")
async def test_sign_default_subject(mock_sign, mock_retrieve, mock_getenv, capsys):
    """Test signing with default subject (issuer as subject)"""
    def getenv_side_effect(key, default=None):
        env_map = {
            "INPUT_OPERATION": "sign",
            "INPUT_AGENT_DID": "did:key:zTestDID",
            "INPUT_MESSAGE": "HelloWorld"
            # No subject_did or expiration_days
        }
        return env_map.get(key, default)
    mock_getenv.side_effect = getenv_side_effect

    # Mock retrieve key
    mock_retrieve.return_value = {"kty":"OKP","d":"secret"}
    # Mock sign
    mock_sign.return_value = "mock_signature"

    await main_async()
    captured = capsys.readouterr()
    output = json.loads(captured.out.strip())
    assert output["status"] == "success"
    
    # Verify sign was called with issuer as subject and default expiration
    mock_sign.assert_called_once_with(
        message="HelloWorld", 
        private_key_jwk={"kty":"OKP","d":"secret"}, 
        issuer_did="did:key:zTestDID",
        subject_did="did:key:zTestDID",  # Same as issuer
        expiration_days=did_utils.DEFAULT_EXPIRATION_DAYS
    )

# Test handle_sign_composite
@pytest.mark.asyncio
@patch("os.getenv")
@patch("src.main.retrieve_agent_private_key", new_callable=AsyncMock)
@patch("src.did_utils.sign_composite")
async def test_sign_composite_happy_path(mock_sign_composite, mock_retrieve, mock_getenv, capsys):
    """Test the composite signing happy path"""
    def getenv_side_effect(key, default=None):
        env_map = {
            "INPUT_OPERATION": "sign_composite",
            "INPUT_AGENT_DID": "did:key:zTestDID",
            "INPUT_RESULT_POINTER": "result123",
            "INPUT_CODE_ID": "code456",
            "INPUT_SUBJECT_DID": "did:key:zSubjectDID",
            "INPUT_EXPIRATION_DAYS": "90"
        }
        return env_map.get(key, default)
    mock_getenv.side_effect = getenv_side_effect

    # Mock retrieve key
    mock_retrieve.return_value = {"kty":"OKP","d":"secret"}
    # Mock sign_composite
    mock_sign_composite.return_value = "mock_composite_signature"

    await main_async()
    captured = capsys.readouterr()
    output = json.loads(captured.out.strip())
    assert output["status"] == "success"
    assert output["signature"] == "mock_composite_signature"
    
    # Verify sign_composite was called with correct params
    mock_sign_composite.assert_called_once_with(
        result_pointer="result123", 
        code_id="code456", 
        private_key_jwk={"kty":"OKP","d":"secret"}, 
        issuer_did="did:key:zTestDID",
        subject_did="did:key:zSubjectDID",
        expiration_days=90
    )

# Test handle_verify
@pytest.mark.asyncio
@patch("os.getenv")
@patch("src.did_utils.verify")
async def test_verify_happy_path(mock_verify, mock_getenv, capsys):
    """Test the verification happy path"""
    def getenv_side_effect(key, default=None):
        env_map = {
            "INPUT_OPERATION": "verify",
            "INPUT_SIGNED_CREDENTIAL": "{\"test\":\"credential\"}",
            "INPUT_EXPECTED_MESSAGE": "HelloWorld",
            "INPUT_EXPECTED_SUBJECT": "did:key:zSubjectDID"
        }
        return env_map.get(key, default)
    mock_getenv.side_effect = getenv_side_effect

    # Mock verify
    mock_verify.return_value = {"valid": True, "contentValid": True}

    await main_async()
    captured = capsys.readouterr()
    output = json.loads(captured.out.strip())
    assert output["status"] == "success"
    assert output["valid"] is True 
    assert output["contentValid"] is True
    
    # Verify verify was called with correct params
    mock_verify.assert_called_once_with(
        signed_credential="{\"test\":\"credential\"}",
        expected_message="HelloWorld",
        expected_subject="did:key:zSubjectDID"
    )

# Test handle_status
@pytest.mark.asyncio
@patch("os.getenv")
@patch("src.did_utils.check_wasm_integrity")
async def test_status_operation(mock_integrity, mock_getenv, capsys):
    """Test the status operation"""
    def getenv_side_effect(key, default=None):
        env_map = {
            "INPUT_OPERATION": "status",
            "VELA_PRODUCTION_MODE": "true",
            "VELA_WASM_HASH": "1234abcd"
        }
        return env_map.get(key, default)
    mock_getenv.side_effect = getenv_side_effect

    # Mock integrity check
    mock_integrity.return_value = {
        "checkPerformed": True,
        "fileExists": True,
        "hashVerified": True,
        "expectedHash": "1234abcd",
        "actualHash": "1234abcd"
    }

    await main_async()
    captured = capsys.readouterr()
    output = json.loads(captured.out.strip())
    assert output["status"] == "success"
    assert output["productionMode"] is True
    assert "wasmIntegrity" in output
    assert output["wasmIntegrity"]["hashVerified"] is True

# Test handle_self_test
@pytest.mark.asyncio
@patch("os.getenv")
@patch("src.did_utils.perform_self_test")
async def test_self_test_operation(mock_self_test, mock_getenv, capsys):
    """Test the self-test operation"""
    def getenv_side_effect(key, default=None):
        env_map = {
            "INPUT_OPERATION": "self_test",
            "VELA_PRODUCTION_MODE": "true"
        }
        return env_map.get(key, default)
    mock_getenv.side_effect = getenv_side_effect

    # Mock self-test
    mock_self_test.return_value = True

    await main_async()
    captured = capsys.readouterr()
    output = json.loads(captured.out.strip())
    assert output["status"] == "success"
    assert "message" in output
    assert "Self-test completed successfully" in output["message"]
    
    # Verify self-test was called
    mock_self_test.assert_called_once() 