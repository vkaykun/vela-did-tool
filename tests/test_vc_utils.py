"""Unit tests for vc_utils module"""

import json
import pytest
from unittest.mock import patch, MagicMock
import datetime
from jwcrypto import jwk

from vela_did_tool.did_utils import generate_did_key_ed25519
from vela_did_tool.vc_utils import (
    sign_credential_jsonld,
    verify_credential_jsonld,
    sign_credential_jwt,
    verify_credential_jwt
)
from vela_did_tool.errors import VcError, SignatureError, InvalidKeyFormatError

@pytest.fixture
def sample_key_material():
    """Generate a DID:key and corresponding key material for testing"""
    did, vm, private_jwk = generate_did_key_ed25519()
    return {
        'did': did,
        'verification_method': vm,
        'private_jwk': private_jwk,
        'verification_method_id': vm.id
    }

@pytest.fixture
def sample_credential(sample_key_material):
    """Create a sample credential for signing"""
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        "type": ["VerifiableCredential"],
        "issuer": sample_key_material['did'],
        "issuanceDate": now,
        "credentialSubject": {
            "id": "did:example:subject",
            "name": "Test Subject",
            "attribute": "Test Value"
        }
    }

@pytest.fixture
def sample_jwt_claims(sample_key_material):
    """Create sample JWT claims for signing"""
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    return {
        "iss": sample_key_material['did'],
        "sub": "did:example:subject",
        "iat": now,
        "exp": now + 3600,
        "vc": {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential"],
            "credentialSubject": {
                "name": "Test Subject"
            }
        }
    }

def mock_normalize(doc, options):
    """Mock implementation of jsonld.normalize for testing"""
    return json.dumps(doc, sort_keys=True)

@patch('vela_did_tool.vc_utils.jsonld.normalize', side_effect=mock_normalize)
def test_sign_verify_jsonld_round_trip(mock_normalize, sample_key_material, sample_credential):
    """Test a full round trip of signing and verifying a JSON-LD credential"""
    proof_options = {
        "verificationMethod": sample_key_material['verification_method_id'],
        "proofPurpose": "assertionMethod"
    }
    
    signed_credential = sign_credential_jsonld(
        sample_credential,
        sample_key_material['private_jwk'],
        proof_options
    )
    
    assert "proof" in signed_credential
    assert "type" in signed_credential["proof"] and signed_credential["proof"]["type"] == "Ed25519Signature2020"
    assert "proofValue" in signed_credential["proof"]
    assert "verificationMethod" in signed_credential["proof"]
    assert "created" in signed_credential["proof"]
    assert "proofPurpose" in signed_credential["proof"]
    
    verified, issuer, error = verify_credential_jsonld(signed_credential)
    
    assert verified is True
    assert issuer == sample_key_material['did']
    assert error is None

@patch('vela_did_tool.vc_utils.jsonld.normalize', side_effect=mock_normalize)
def test_verify_jsonld_tampered(mock_normalize, sample_key_material, sample_credential):
    """Test verification fails when credential is tampered with"""

    proof_options = {
        "verificationMethod": sample_key_material['verification_method_id'],
        "proofPurpose": "assertionMethod"
    }
    
    signed_credential = sign_credential_jsonld(
        sample_credential,
        sample_key_material['private_jwk'],
        proof_options
    )
    
    tampered_credential = signed_credential.copy()
    tampered_credential["credentialSubject"]["attribute"] = "Tampered Value"
    
    verified, issuer, error = verify_credential_jsonld(tampered_credential)
    
    assert verified is False
    assert issuer is None
    assert error is not None
    assert "Invalid signature" in error

def test_sign_jsonld_missing_verification_method(sample_credential, sample_key_material):
    """Test error when verification method is missing"""
    proof_options = {
        "proofPurpose": "assertionMethod"
    }
    
    with pytest.raises(VcError) as excinfo:
        sign_credential_jsonld(
            sample_credential,
            sample_key_material['private_jwk'],
            proof_options
        )
    
    assert "Missing 'verificationMethod'" in str(excinfo.value)

def test_sign_jsonld_invalid_key(sample_credential, sample_key_material):
    """Test error when private key is invalid"""
    proof_options = {
        "verificationMethod": sample_key_material['verification_method_id'],
        "proofPurpose": "assertionMethod"
    }
    
    invalid_key = {k: v for k, v in sample_key_material['private_jwk'].items() if k != 'd'}
    
    with pytest.raises(InvalidKeyFormatError) as excinfo:
        sign_credential_jsonld(
            sample_credential,
            invalid_key,
            proof_options
        )
    
    assert "Private JWK must contain 'd' component" in str(excinfo.value)

def test_verify_jsonld_missing_proof():
    """Test verification fails when proof is missing"""
    credential = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential"],
        "issuer": "did:key:z123",
        "credentialSubject": {"id": "did:example:subject"}
    }
    
    verified, issuer, error = verify_credential_jsonld(credential)
    
    assert verified is False
    assert issuer is None
    assert "missing 'proof' block" in error.lower()

def test_verify_jsonld_incomplete_proof(sample_credential):
    """Test verification fails when proof is incomplete"""
    credential_with_incomplete_proof = sample_credential.copy()
    credential_with_incomplete_proof["proof"] = {
        "type": "Ed25519Signature2020",
    }
    
    verified, issuer, error = verify_credential_jsonld(credential_with_incomplete_proof)
    
    assert verified is False
    assert issuer is None
    assert "missing required fields" in error.lower()

def test_sign_verify_jwt_round_trip(sample_key_material, sample_jwt_claims):
    """Test a full round trip of signing and verifying a JWT credential"""
    signed_jwt = sign_credential_jwt(
        sample_jwt_claims,
        sample_key_material['did'],
        sample_key_material['private_jwk']
    )
    
    assert isinstance(signed_jwt, str)
    assert len(signed_jwt.split(".")) == 3
    
    verified, issuer, payload, error = verify_credential_jwt(signed_jwt)
    
    assert verified is True
    assert issuer == sample_key_material['did']
    assert payload is not None
    assert payload["iss"] == sample_key_material['did']
    assert "vc" in payload
    assert error is None

def test_sign_jwt_mismatched_issuer(sample_key_material, sample_jwt_claims):
    """Test that JWT with mismatched issuer raises an error"""
    original_iss = sample_jwt_claims["iss"]
    sample_jwt_claims["iss"] = "did:key:different"
    
    with pytest.raises(VcError) as exc_info:
        sign_credential_jwt(
            sample_jwt_claims,
            sample_key_material['did'],
            sample_key_material['private_jwk']
        )
    
    error_message = str(exc_info.value)
    assert "must include 'iss' field matching" in error_message
    assert sample_key_material['did'] in error_message

def test_verify_jwt_tampered(sample_key_material, sample_jwt_claims):
    """Test verification fails for a tampered JWT"""
    signed_jwt = sign_credential_jwt(
        sample_jwt_claims,
        sample_key_material['did'],
        sample_key_material['private_jwk']
    )
    
    parts = signed_jwt.split('.')
    tampered_signature = parts[2][:-5] + "XXXXX"
    tampered_jwt = parts[0] + '.' + parts[1] + '.' + tampered_signature
    
    print(f"\nORIGINAL JWT: {signed_jwt}")
    print(f"TAMPERED JWT: {tampered_jwt}")
    
    verified, issuer, payload, error = verify_credential_jwt(tampered_jwt)
    
    print(f"VERIFICATION RESULT: verified={verified}, issuer={issuer}, error={error}")
    
    assert verified is False
    assert issuer is None
    assert payload is None
    assert error is not None
    assert "JWT" in error or "signature" in error

def test_verify_jwt_invalid_format():
    """Test verification fails for an invalid JWT format"""
    invalid_jwt = "not.a.jwt"
    
    verified, issuer, payload, error = verify_credential_jwt(invalid_jwt)
    
    assert verified is False
    assert issuer is None
    assert payload is None
    assert "Invalid JWT format" in error 