"""Unit tests for did_utils module"""

import os
import json
import pytest
from unittest.mock import patch, MagicMock
from jwcrypto import jwk

from vela_did_tool.did_utils import (
    sanitize_did_for_env, 
    get_private_jwk_from_env, 
    generate_did_key_ed25519, 
    get_public_key_bytes_from_did
)
from vela_did_tool.constants import (
    NAPTHA_SECRET_PREFIX,
    DID_KEY_PREFIX,
    MULTIBASE_BASE58BTC_PREFIX,
    MULTICODEC_ED25519_PUB_HEADER
)
from vela_did_tool.errors import KeyNotFoundError, InvalidKeyFormatError, DidError, ConfigurationError


@pytest.fixture
def sample_private_jwk():
    """Create a sample Ed25519 JWK for testing"""
    key = jwk.JWK.generate(kty='OKP', crv='Ed25519')
    return json.loads(key.export_private())

@pytest.fixture
def sample_did_and_jwk():
    """Generate a real did:key and corresponding JWK for testing"""
    did, vm, private_jwk = generate_did_key_ed25519()
    return did, private_jwk

def test_sanitize_did_for_env():
    """Test that DIDs are properly sanitized for environment variable names"""
    did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    sanitized = sanitize_did_for_env(did)
    assert sanitized == "did_key_z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    
    did = "did:web:example.com"
    sanitized = sanitize_did_for_env(did)
    assert sanitized == "did_web_example_com"
    
    with pytest.raises(TypeError):
        sanitize_did_for_env(None)

@patch('vela_did_tool.did_utils.os.getenv')
def test_get_private_jwk_from_env_success(mock_getenv):
    """Test successful retrieval of private JWK from environment variable."""
    test_did = "did:key:z6MkTestingEnvKey"
    
    expected_env_var = f"{NAPTHA_SECRET_PREFIX}did_key_z6MkTestingEnvKey"
    
    mock_jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "d": "mock_private_key_data",
        "x": "mock_public_key_data"
    }
    
    mock_getenv.return_value = json.dumps(mock_jwk)
    
    result = get_private_jwk_from_env(test_did)
    
    mock_getenv.assert_called_once_with(expected_env_var)
    
    assert result == mock_jwk

@patch('vela_did_tool.did_utils.os.getenv')
def test_get_private_jwk_from_env_missing(mock_getenv):
    """Test behavior when environment variable for DID is not found."""
    test_did = "did:key:z6MkMissingKey"
    
    expected_env_var = f"{NAPTHA_SECRET_PREFIX}did_key_z6MkMissingKey"
    
    mock_getenv.return_value = None
    
    with pytest.raises(KeyNotFoundError) as excinfo:
        get_private_jwk_from_env(test_did)
    
    error_message = str(excinfo.value)
    assert test_did in error_message
    assert expected_env_var in error_message
    assert "not found" in error_message

@patch('vela_did_tool.did_utils.os.getenv')
def test_get_private_jwk_from_env_invalid_json(mock_getenv):
    """Test behavior when environment variable contains invalid JSON."""
    test_did = "did:key:z6MkInvalidJsonKey"
    expected_env_var = f"{NAPTHA_SECRET_PREFIX}did_key_z6MkInvalidJsonKey"
    
    mock_getenv.return_value = "{ This is not valid JSON"
    
    with pytest.raises(InvalidKeyFormatError) as excinfo:
        get_private_jwk_from_env(test_did)
    
    error_message = str(excinfo.value)
    assert "Failed to parse JSON" in error_message
    assert expected_env_var in error_message

@patch('vela_did_tool.did_utils.os.getenv')
def test_get_private_jwk_from_env_not_jwk(mock_getenv):
    """Test error when environment variable contains valid JSON but not a JWK"""
    did = "did:key:z6MkTestKey"
    mock_getenv.return_value = json.dumps({"not": "a jwk"})
    
    with pytest.raises(InvalidKeyFormatError):
        get_private_jwk_from_env(did)

@patch('vela_did_tool.did_utils.sanitize_did_for_env')
def test_get_private_jwk_from_env_config_error(mock_sanitize):
    """Test error when constructing environment variable name fails"""
    did = "did:key:z6MkTestKey"
    mock_sanitize.side_effect = Exception("Test exception")
    
    with pytest.raises(ConfigurationError):
        get_private_jwk_from_env(did)

def test_generate_did_key_ed25519():
    """Test generation of a did:key identifier and key pair"""
    did, verification_method, private_jwk = generate_did_key_ed25519()
    
    assert did.startswith(DID_KEY_PREFIX)
    assert did.replace(DID_KEY_PREFIX, '').startswith(MULTIBASE_BASE58BTC_PREFIX)
    
    assert verification_method.id == f"{did}#{did.replace(DID_KEY_PREFIX, '')}"
    assert verification_method.type == "Ed25519VerificationKey2020"
    assert verification_method.controller == did
    assert verification_method.publicKeyMultibase == did.replace(DID_KEY_PREFIX, '')
    
    assert 'kty' in private_jwk and private_jwk['kty'] == 'OKP'
    assert 'crv' in private_jwk and private_jwk['crv'] == 'Ed25519'
    assert 'd' in private_jwk
    assert 'x' in private_jwk
    
    public_key_bytes = get_public_key_bytes_from_did(did)
    assert len(public_key_bytes) == 32

def test_get_public_key_bytes_from_did_valid(sample_did_and_jwk):
    """Test extracting public key bytes from a valid did:key"""
    did, _ = sample_did_and_jwk
    
    key_bytes = get_public_key_bytes_from_did(did)
    
    assert isinstance(key_bytes, bytes)
    assert len(key_bytes) == 32

def test_get_public_key_bytes_from_did_invalid_prefix():
    """Test error when did:key prefix is invalid"""
    did = "did:invalid:z6MkhNotAValidPrefix"
    
    with pytest.raises(DidError) as excinfo:
        get_public_key_bytes_from_did(did)
    assert "Invalid DID format" in str(excinfo.value)

def test_get_public_key_bytes_from_did_invalid_multibase():
    """Test error when multibase prefix is invalid"""
    did = f"{DID_KEY_PREFIX}y6MkInvalidMultibasePrefix"
    
    with pytest.raises(DidError) as excinfo:
        get_public_key_bytes_from_did(did)
    assert "Unsupported multibase encoding" in str(excinfo.value)

def test_get_public_key_bytes_from_did_invalid_multicodec():
    """Test error when multicodec header is invalid"""
    pass 