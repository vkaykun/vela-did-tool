# context_loader.py

"""
Provides offline-friendly JSON-LD context loading for Naptha environments.

This module pre-bundles common contexts used for Verifiable Credentials
to avoid network calls during JSON-LD processing, making the library
more suitable for restricted network environments like Naptha Nodes.
"""

import json
import logging
from typing import Dict, Any, Callable, Optional
from pyld import jsonld

logger = logging.getLogger(__name__)

CONTEXTS = {
    # W3C Verifiable Credentials Context v1
    "https://www.w3.org/2018/credentials/v1": {
        "@version": 1.1,
        "@protected": True,
        "id": "@id",
        "type": "@type",
        # Simplified definitions - rely on SECURITY_CONTEXT_V2 for proof details
        "VerifiableCredential": {"@id": "https://www.w3.org/2018/credentials#VerifiableCredential"},
        "VerifiablePresentation": {"@id": "https://www.w3.org/2018/credentials#VerifiablePresentation"},
        "EcdsaSecp256k1Signature2019": {"@id": "https://w3id.org/security#EcdsaSecp256k1Signature2019"},
        "Ed25519Signature2020": {"@id": "https://w3id.org/security#Ed25519Signature2020"},
        # Expanded definitions for prefixes
        "cred": {"@id": "https://www.w3.org/2018/credentials#"},
        "sec": {"@id": "https://w3id.org/security#"},
        "xsd": {"@id": "http://www.w3.org/2001/XMLSchema#"},
        # Property definitions
        "credentialSchema": {"@id": "cred:credentialSchema", "@type": "@id"},
        "credentialStatus": {"@id": "cred:credentialStatus", "@type": "@id"},
        "credentialSubject": {"@id": "cred:credentialSubject", "@type": "@id"},
        "evidence": {"@id": "cred:evidence", "@type": "@id"},
        "expirationDate": {"@id": "cred:expirationDate", "@type": "xsd:dateTime"},
        "holder": {"@id": "cred:holder", "@type": "@id"},
        "issued": {"@id": "cred:issued", "@type": "xsd:dateTime"},
        "issuer": {"@id": "cred:issuer", "@type": "@id"},
        "issuanceDate": {"@id": "cred:issuanceDate", "@type": "xsd:dateTime"},
        "proof": {"@id": "sec:proof", "@type": "@id", "@container": "@graph"},
        "refreshService": {"@id": "cred:refreshService", "@type": "@id"},
        "termsOfUse": {"@id": "cred:termsOfUse", "@type": "@id"},
        "validFrom": {"@id": "cred:validFrom", "@type": "xsd:dateTime"},
        "validUntil": {"@id": "cred:validUntil", "@type": "xsd:dateTime"}
    },

    # Security Ed25519 2020 Context
    "https://w3id.org/security/suites/ed25519-2020/v1": {
        "@version": 1.1,
        "@protected": True,
        "id": "@id",
        "type": "@type",
        # Expanded definitions for prefixes
        "sec": {"@id": "https://w3id.org/security#"},
        "xsd": {"@id": "http://www.w3.org/2001/XMLSchema#"},
        # Define terms used within the proof structure
        "Ed25519VerificationKey2020": {"@id": "https://w3id.org/security#Ed25519VerificationKey2020"},
        "Ed25519Signature2020": {"@id": "https://w3id.org/security#Ed25519Signature2020"},
        "controller": {"@id": "sec:controller", "@type": "@id"},
        "revoked": {"@id": "sec:revoked", "@type": "xsd:dateTime"},
        "publicKeyMultibase": {"@id": "sec:publicKeyMultibase"},
        "challenge": {"@id": "sec:challenge"},
        "created": {"@id": "http://purl.org/dc/terms/created", "@type": "xsd:dateTime"},
        "domain": {"@id": "sec:domain"},
        "expires": {"@id": "sec:expiration", "@type": "xsd:dateTime"},
        "nonce": {"@id": "sec:nonce"},
        "proofPurpose": {"@id": "sec:proofPurpose", "@type": "@vocab"},
        "proofValue": {"@id": "sec:proofValue"},
        "verificationMethod": {"@id": "sec:verificationMethod", "@type": "@id"},
        "assertionMethod": {"@id": "sec:assertionMethod", "@type": "@id", "@container": "@set"},
        "authentication": {"@id": "sec:authenticationMethod", "@type": "@id", "@container": "@set"}
    }
}

def create_document_loader() -> Callable:
    """
    Creates a custom document loader that first checks the bundled contexts
    and falls back to network loading only if necessary.
    
    Returns:
        A document loader function compatible with PyLD.
    """
    def document_loader(url: str, *args, **kwargs) -> Dict[str, Any]:
        """
        Custom document loader for JSON-LD processing. Accepts extra args/kwargs.
        
        Args:
            url: The URL of the context to load.
            *args: Additional positional arguments (ignored).
            **kwargs: Additional keyword arguments (ignored).
            
        Returns:
            A document object with context data.
            
        Raises:
            jsonld.JsonLdError: If the context cannot be loaded.
        """
        logger.debug(f"Requesting JSON-LD context: {url}")
        if args: logger.debug(f"Document loader received extra args: {args}")
        if kwargs: logger.debug(f"Document loader received extra kwargs: {kwargs}")
        
        if url in CONTEXTS:
            logger.info(f"Using bundled context for: {url}")
            try:
                # Return a simplified version of the context to avoid nested context issues
                context_data = CONTEXTS[url]
                # If the context has nested @context properties, flatten them
                if isinstance(context_data, dict):
                    flattened_context = context_data.copy()
                    # Remove problematic nested @context properties from definitions
                    for key, value in flattened_context.items():
                        if isinstance(value, dict) and '@context' in value:
                            # Remove nested @context to prevent processing errors
                            value_copy = value.copy()
                            value_copy.pop('@context', None)
                            flattened_context[key] = value_copy
                    
                    return {
                        'contextUrl': None,
                        'documentUrl': url,
                        'document': flattened_context
                    }
                
                return {
                    'contextUrl': None,
                    'documentUrl': url,
                    'document': context_data
                }
            except Exception as e:
                logger.warning(f"Error processing bundled context, using fallback: {e}")
                # If there's any issue with the bundled context, fall back to a simpler approach
                pass
        
        # For core contexts, provide a minimal context that won't cause normalization issues
        if url == "https://www.w3.org/2018/credentials/v1":
            logger.info(f"Using simplified fallback for credentials context")
            return {
                'contextUrl': None,
                'documentUrl': url,
                'document': {
                    "@context": {
                        "@version": 1.1,
                        "id": "@id",
                        "type": "@type",
                        "VerifiableCredential": "https://www.w3.org/2018/credentials#VerifiableCredential",
                        "credentialSubject": "https://www.w3.org/2018/credentials#credentialSubject",
                        "issuer": "https://www.w3.org/2018/credentials#issuer",
                        "issuanceDate": {
                            "@id": "https://www.w3.org/2018/credentials#issuanceDate",
                            "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
                        },
                        "proof": "https://w3id.org/security#proof"
                    }
                }
            }
        elif url == "https://w3id.org/security/suites/ed25519-2020/v1":
            logger.info(f"Using simplified fallback for Ed25519-2020 context")
            return {
                'contextUrl': None,
                'documentUrl': url,
                'document': {
                    "@context": {
                        "@version": 1.1,
                        "id": "@id",
                        "type": "@type",
                        "Ed25519Signature2020": "https://w3id.org/security#Ed25519Signature2020",
                        "Ed25519VerificationKey2020": "https://w3id.org/security#Ed25519VerificationKey2020",
                        "verificationMethod": "https://w3id.org/security#verificationMethod",
                        "proofPurpose": "https://w3id.org/security#proofPurpose",
                        "assertionMethod": "https://w3id.org/security#assertionMethod",
                        "proofValue": "https://w3id.org/security#proofValue",
                        "created": {
                            "@id": "http://purl.org/dc/terms/created",
                            "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
                        }
                    }
                }
            }
        
        logger.warning(
            f"Context {url} not found in bundled contexts. "
            f"Attempting to load from network using default loader. "
            f"This may fail in restricted network environments."
        )
        
        try:
            options = kwargs.get('options', {})
            # Ensure the default loader is used for network fallback
            return jsonld.load_document(url, options={'documentLoader': jsonld.requests_document_loader(), **options})
        except Exception as e:
            logger.error(f"Failed to load context from network: {url}, Error: {e}")
            raise jsonld.JsonLdError(
                 'Loading remote context failed',
                 'jsonld.LoadContextError',
                 code='loading remote context failed',
                 url=url,
                 cause=e
            )

    return document_loader

default_document_loader = create_document_loader() 