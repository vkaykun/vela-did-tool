"""
Unit tests for the run module.
"""

import json
import pytest
from unittest.mock import patch, MagicMock, mock_open
import tempfile
import os

from vela_did_tool.run import run
from vela_did_tool.errors import VcError


def test_main_invalid_json():
    """Test handling invalid JSON input."""
    with pytest.raises(VcError) as excinfo:
        run({})  # Missing func_name parameter
    
    assert "Missing 'func_name' parameter" in str(excinfo.value)


def test_main_unknown_func_name():
    """Test handling unknown function name."""
    with pytest.raises(VcError) as excinfo:
        run({"func_name": "unknown_function"})
    
    assert "Unknown function: unknown_function" in str(excinfo.value)


@patch('vela_did_tool.run.generate_did_key_ed25519')
def test_generate_did_key(mock_generate):
    """Test generate_did_key function."""
    mock_did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    mock_public_jwk = {"kty": "OKP", "crv": "Ed25519", "x": "test_public_key"}
    mock_private_jwk = {"kty": "OKP", "crv": "Ed25519", "x": "test_public_key", "d": "test_private_key"}
    
    mock_generate.return_value = (mock_did, mock_public_jwk, mock_private_jwk)
    
    # Test without output file
    result = run({"func_name": "generate", "key_type": "ed25519"})
    
    assert result["did"] == mock_did
    assert result["publicKey"] == mock_public_jwk
    assert result["privateKey"] == mock_private_jwk
    mock_generate.assert_called_once()


@patch('vela_did_tool.run.generate_did_key_ed25519')
@patch('vela_did_tool.run.write_json_file')
def test_generate_did_key_with_output(mock_write, mock_generate):
    """Test generate_did_key function with output file."""
    mock_did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    mock_public_jwk = {"kty": "OKP", "crv": "Ed25519", "x": "test_public_key"}
    mock_private_jwk = {"kty": "OKP", "crv": "Ed25519", "x": "test_public_key", "d": "test_private_key"}
    
    mock_generate.return_value = (mock_did, mock_public_jwk, mock_private_jwk)
    
    output_file = "test_output.json"
    result = run({"func_name": "generate", "key_type": "ed25519", "output": output_file})
    
    assert result["did"] == mock_did
    mock_write.assert_called_once()
    args, _ = mock_write.call_args
    assert args[0]["did"] == mock_did
    assert args[1] == output_file


@patch('vela_did_tool.run.resolve_did')
def test_resolve_did_document(mock_resolve):
    """Test resolve_did_document function."""
    mock_did_doc = {
        "@context": "https://www.w3.org/ns/did/v1",
        "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    }
    
    mock_resolve.return_value = mock_did_doc
    
    result = run({"func_name": "resolve", "did": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"})
    
    assert result == mock_did_doc
    mock_resolve.assert_called_once_with("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")


def test_resolve_did_missing_did():
    """Test resolve_did_document with missing DID parameter."""
    with pytest.raises(VcError) as excinfo:
        run({"func_name": "resolve"})
    
    assert "Missing 'did' parameter" in str(excinfo.value)


@patch('vela_did_tool.run.load_json_file')
@patch('vela_did_tool.run.sign_credential_jsonld')
def test_sign_credential_jsonld(mock_sign, mock_load):
    """Test sign_credential with JSON-LD format."""
    mock_private_jwk = {"kty": "OKP", "crv": "Ed25519", "d": "test_private_key"}
    mock_credential = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential"],
        "issuer": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    }
    mock_signed = {**mock_credential, "proof": {"type": "Ed25519Signature2020"}}
    
    mock_load.side_effect = [mock_private_jwk, mock_credential]
    mock_sign.return_value = mock_signed
    
    result = run({
        "func_name": "sign", 
        "func_input_data": {
            "format": "jsonld", 
            "key": "test_key.json", 
            "credential": "test_cred.json"
        }
    })
    
    assert result == mock_signed
    mock_sign.assert_called_once()
    args, _ = mock_sign.call_args
    assert args[0] == mock_credential
    assert args[1] == mock_private_jwk
    assert args[2]["verificationMethod"].startswith(mock_credential["issuer"])
    
    mock_sign.reset_mock()
    mock_load.reset_mock()
    mock_load.side_effect = [mock_private_jwk, mock_credential]
    mock_sign.return_value = mock_signed
    
    result = run({
        "func": "sign", 
        "format": "jsonld", 
        "key": "test_key.json", 
        "credential": "test_cred.json"
    })
    
    assert result == mock_signed
    mock_sign.assert_called_once()


@patch('vela_did_tool.run.load_json_file')
@patch('vela_did_tool.run.sign_credential_jwt')
def test_sign_credential_jwt(mock_sign, mock_load):
    """Test sign_credential with JWT format."""
    mock_private_jwk = {"kty": "OKP", "crv": "Ed25519", "d": "test_private_key"}
    mock_credential = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential"]
    }
    mock_jwt = "eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJkaWQ6a2V5OnRlc3QifQ.signature"
    
    mock_load.side_effect = [mock_private_jwk, mock_credential]
    mock_sign.return_value = mock_jwt
    
    result = run({
        "func_name": "sign", 
        "func_input_data": {
            "format": "jwt", 
            "key": "test_key.json", 
            "credential": "test_cred.json",
            "issuer_did": "did:key:test"
        }
    })
    
    assert result == {"jwt": mock_jwt}
    mock_sign.assert_called_once()
    args, _ = mock_sign.call_args
    assert args[0]["vc"] == mock_credential
    assert args[0]["iss"] == "did:key:test"
    assert args[1] == "did:key:test"
    assert args[2] == mock_private_jwk


@patch('vela_did_tool.run.get_private_jwk_from_env')
@patch('vela_did_tool.run.load_json_file')
@patch('vela_did_tool.run.sign_credential_jsonld')
def test_sign_credential_with_agent_did(mock_sign, mock_load, mock_get_jwk):
    """Test sign_credential using agent_did to retrieve the key."""
    agent_did = "did:key:z6MkAgentDid"
    mock_private_jwk = {"kty": "OKP", "crv": "Ed25519", "d": "test_private_key"}
    mock_credential = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential"],
    }
    mock_signed = {**mock_credential, "proof": {"type": "Ed25519Signature2020"}}
    
    mock_get_jwk.return_value = mock_private_jwk
    mock_load.return_value = mock_credential
    mock_sign.return_value = mock_signed
    
    result = run({
        "func_name": "sign", 
        "func_input_data": {
            "credential_format": "jsonld", 
            "agent_did": agent_did,
            "credential": "test_cred.json"
        }
    })
    
    assert result == mock_signed
    mock_get_jwk.assert_called_once_with(agent_did)
    mock_sign.assert_called_once()
    args, _ = mock_sign.call_args
    assert args[0] == mock_credential
    assert args[1] == mock_private_jwk
    assert args[2]["verificationMethod"].startswith(agent_did)


def test_sign_missing_parameters():
    """Test sign_credential with missing parameters."""
    with pytest.raises(VcError) as excinfo:
        run({
            "func_name": "sign", 
            "func_input_data": {
                "credential": "test.json"
            }
        })
    
    assert "Missing both 'agent_did' and 'key'" in str(excinfo.value)
    
    with pytest.raises(VcError) as excinfo:
        run({
            "func_name": "sign", 
            "func_input_data": {
                "key": "test.json"
            }
        })
    
    assert "Missing 'credential' parameter" in str(excinfo.value)


@patch('vela_did_tool.run.load_json_file')
@patch('vela_did_tool.run.verify_credential_jsonld')
def test_verify_credential_jsonld(mock_verify, mock_load):
    """Test verify_credential with JSON-LD format."""
    mock_credential = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential"],
        "issuer": "did:key:test",
        "proof": {"type": "Ed25519Signature2020"}
    }
    
    mock_load.return_value = mock_credential
    mock_verify.return_value = (True, "did:key:test", None)
    
    result = run({
        "func": "verify", 
        "format": "jsonld", 
        "credential": "test_cred.json"
    })
    
    assert result["verified"] is True
    assert result["issuer"] == "did:key:test"
    assert "error" not in result
    mock_verify.assert_called_once_with(mock_credential)


@patch('vela_did_tool.run.verify_credential_jsonld')
@patch('vela_did_tool.run.load_json_file')
def test_verify_credential_jsonld_failure(mock_load, mock_verify):
    """Test verify_credential with JSON-LD format when verification fails."""
    mock_credential = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential"],
        "issuer": "did:key:test",
        "proof": {"type": "Ed25519Signature2020"}
    }
    
    mock_load.return_value = mock_credential
    mock_verify.return_value = (False, None, "Invalid signature")
    
    result = run({
        "func": "verify", 
        "format": "jsonld", 
        "credential": "test_cred.json"
    })
    
    assert result["verified"] is False
    assert result["issuer"] is None
    assert result["error"] == "Invalid signature"


@patch('builtins.open', new_callable=mock_open, read_data="eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJkaWQ6a2V5OnRlc3QifQ.signature")
@patch('vela_did_tool.run.verify_credential_jwt')
def test_verify_credential_jwt(mock_verify, mock_file):
    """Test verify_credential with JWT format."""
    mock_payload = {"iss": "did:key:test", "vc": {}}
    mock_verify.return_value = (True, "did:key:test", mock_payload, None)
    
    result = run({
        "func": "verify", 
        "format": "jwt", 
        "credential": "test.jwt"
    })
    
    assert result["verified"] is True
    assert result["issuer"] == "did:key:test"
    assert result["payload"] == mock_payload
    assert "error" not in result
    mock_verify.assert_called_once_with("eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJkaWQ6a2V5OnRlc3QifQ.signature")


def test_verify_missing_parameters():
    """Test verify_credential with missing parameters."""
    with pytest.raises(VcError) as excinfo:
        run({"func": "verify"})
    
    assert "Missing 'credential' parameter" in str(excinfo.value)


@patch('vela_did_tool.run.get_private_jwk_from_env')
@patch('vela_did_tool.run.load_json_file')
@patch('vela_did_tool.run.sign_credential_jsonld')
def test_sign_credential_with_naptha_env(mock_sign, mock_load, mock_get_jwk):
    """Test sign_credential with agent_did parameter in Naptha environment."""
    agent_did = "did:key:z6MkNapthaTestDid"
    mock_private_jwk = {"kty": "OKP", "crv": "Ed25519", "d": "test_naptha_private_key", "x": "test_public_key"}
    mock_credential = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential"]
    }
    mock_signed = {**mock_credential, "proof": {"type": "Ed25519Signature2020"}}
    
    mock_get_jwk.return_value = mock_private_jwk
    mock_load.return_value = mock_credential
    mock_sign.return_value = mock_signed
    
    result = run({
        "func_name": "sign", 
        "func_input_data": {
            "credential_format": "jsonld", 
            "agent_did": agent_did,
            "credential": "test_cred.json"
        }
    })
    
    assert result == mock_signed
    
    mock_get_jwk.assert_called_once_with(agent_did)
    mock_load.assert_called_once()
    mock_sign.assert_called_once()
    
    args, _ = mock_sign.call_args
    assert args[0] == mock_credential
    assert args[1] == mock_private_jwk
    assert args[2]["verificationMethod"].startswith(agent_did)


@patch('vela_did_tool.run.get_private_jwk_from_env')
@patch('vela_did_tool.run.load_json_file')
def test_sign_credential_with_naptha_env_missing_key(mock_load, mock_get_jwk):
    """Test sign_credential with agent_did parameter when environment key is not found."""
    agent_did = "did:key:z6MkMissingKeyDid"
    mock_credential = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential"]
    }
    
    from vela_did_tool.errors import KeyNotFoundError
    mock_get_jwk.side_effect = KeyNotFoundError(f"Secret environment variable not found for DID '{agent_did}'.")
    mock_load.return_value = mock_credential
    
    with pytest.raises(VcError) as excinfo:
        run({
            "func_name": "sign", 
            "func_input_data": {
                "credential_format": "jsonld", 
                "agent_did": agent_did,
                "credential": "test_cred.json"
            }
        })
    
    error_message = str(excinfo.value)
    assert "Failed to retrieve private key for agent DID" in error_message
    
    mock_get_jwk.assert_called_once_with(agent_did)
    mock_load.assert_not_called()


@patch('vela_did_tool.did_utils.os.getenv')
@patch('vela_did_tool.run.load_json_file')
@patch('vela_did_tool.run.sign_credential_jwt')
def test_sign_jwt_with_naptha_env(mock_sign, mock_load, mock_getenv):
    """Test JWT signing with agent_did parameter in a Naptha environment."""
    agent_did = "did:key:z6MkNapthaTestDidJwt"
    
    from vela_did_tool.constants import NAPTHA_SECRET_PREFIX
    naptha_env_var = f"{NAPTHA_SECRET_PREFIX}did_key_z6MkNapthaTestDidJwt"
    mock_private_jwk = {"kty": "OKP", "crv": "Ed25519", "d": "test_naptha_private_key", "x": "test_public_key"}
    mock_getenv.return_value = json.dumps(mock_private_jwk)
    
    mock_credential = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential"]
    }
    mock_jwt = "eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJkaWQ6a2V5Ono2TWtOYXB0aGFUZXN0RGlkSnd0In0.signature"
    
    mock_load.return_value = mock_credential
    mock_sign.return_value = mock_jwt
    
    result = run({
        "func_name": "sign", 
        "func_input_data": {
            "credential_format": "jwt", 
            "agent_did": agent_did,
            "credential": "test_cred.json"
        }
    })
    
    assert result == {"jwt": mock_jwt}
    
    mock_getenv.assert_called_with(naptha_env_var)
    mock_load.assert_called_once()
    mock_sign.assert_called_once()
    
    args, kwargs = mock_sign.call_args
    assert args[0]["vc"] == mock_credential
    assert args[0]["iss"] == agent_did
    assert args[1] == agent_did
    assert args[2] == mock_private_jwk