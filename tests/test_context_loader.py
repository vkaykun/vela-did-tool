# tests/test_context_loader.py

"""Unit tests for the context_loader module."""

import pytest
from unittest.mock import patch, MagicMock
from pyld import jsonld

from vela_did_tool.context_loader import (
    CONTEXTS, 
    create_document_loader,
    default_document_loader
)


def test_bundled_contexts_structure():
    """Test that our bundled contexts have the correct structure."""
    assert "https://www.w3.org/2018/credentials/v1" in CONTEXTS
    assert "https://w3id.org/security/suites/ed25519-2020/v1" in CONTEXTS
    
    vc_context = CONTEXTS["https://www.w3.org/2018/credentials/v1"]
    assert "@context" in vc_context
    assert "VerifiableCredential" in vc_context["@context"]
    
    ed25519_context = CONTEXTS["https://w3id.org/security/suites/ed25519-2020/v1"]
    assert "@context" in ed25519_context
    assert "Ed25519Signature2020" in ed25519_context["@context"]


def test_document_loader_with_bundled_context():
    """Test that the document loader correctly returns bundled contexts."""
    doc_loader = create_document_loader()
    
    result = doc_loader("https://www.w3.org/2018/credentials/v1")
    
    assert "contextUrl" in result
    assert "documentUrl" in result
    assert "document" in result
    
    assert result["documentUrl"] == "https://www.w3.org/2018/credentials/v1"
    assert result["document"] == CONTEXTS["https://www.w3.org/2018/credentials/v1"]


@patch('vela_did_tool.context_loader.jsonld.load_document')
def test_document_loader_fallback(mock_load_document):
    """Test that the document loader falls back to network loading for unknown contexts."""
    mock_result = {"contextUrl": None, "documentUrl": "https://example.com/context", "document": {"@context": {}}}
    mock_load_document.return_value = mock_result
    
    doc_loader = create_document_loader()
    
    result = doc_loader("https://example.com/context")
    
    mock_load_document.assert_called_once_with("https://example.com/context")
    assert result == mock_result


@patch('vela_did_tool.context_loader.jsonld.load_document')
def test_document_loader_fallback_error(mock_load_document):
    """Test that the document loader handles errors from the fallback loader."""
    mock_load_document.side_effect = Exception("Network error")
    
    doc_loader = create_document_loader()
    
    with pytest.raises(jsonld.JsonLdError) as excinfo:
        doc_loader("https://example.com/context")
    
    assert "Network loading failed and context was not pre-bundled" in str(excinfo.value)


def test_default_document_loader():
    """Test that the default document loader instance works properly."""
    assert callable(default_document_loader)
    
    result = default_document_loader("https://www.w3.org/2018/credentials/v1")
    assert "document" in result
    assert result["documentUrl"] == "https://www.w3.org/2018/credentials/v1" 