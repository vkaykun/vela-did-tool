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
        "@context": {
            "@version": 1.1,
            "@protected": True,
            "id": "@id",
            "type": "@type",
            "VerifiableCredential": {
                "@id": "https://www.w3.org/2018/credentials#VerifiableCredential",
                "@context": {
                    "@version": 1.1,
                    "@protected": True,
                    "id": "@id",
                    "type": "@type",
                    "cred": "https://www.w3.org/2018/credentials#",
                    "sec": "https://w3id.org/security#",
                    "xsd": "http://www.w3.org/2001/XMLSchema#",
                    "credentialSchema": {
                        "@id": "cred:credentialSchema",
                        "@type": "@id",
                        "@context": {
                            "@version": 1.1,
                            "@protected": True,
                            "id": "@id",
                            "type": "@type",
                            "cred": "https://www.w3.org/2018/credentials#",
                            "JsonSchemaValidator2018": "cred:JsonSchemaValidator2018"
                        }
                    },
                    "credentialStatus": {"@id": "cred:credentialStatus", "@type": "@id"},
                    "credentialSubject": {"@id": "cred:credentialSubject", "@type": "@id"},
                    "evidence": {"@id": "cred:evidence", "@type": "@id"},
                    "expirationDate": {"@id": "cred:expirationDate", "@type": "xsd:dateTime"},
                    "holder": {"@id": "cred:holder", "@type": "@id"},
                    "issued": {"@id": "cred:issued", "@type": "xsd:dateTime"},
                    "issuer": {"@id": "cred:issuer", "@type": "@id"},
                    "issuanceDate": {"@id": "cred:issuanceDate", "@type": "xsd:dateTime"},
                    "proof": {"@id": "sec:proof", "@type": "@id", "@container": "@graph"},
                    "refreshService": {
                        "@id": "cred:refreshService",
                        "@type": "@id",
                        "@context": {
                            "@version": 1.1,
                            "@protected": True,
                            "id": "@id",
                            "type": "@type",
                            "cred": "https://www.w3.org/2018/credentials#",
                            "ManualRefreshService2018": "cred:ManualRefreshService2018"
                        }
                    },
                    "termsOfUse": {"@id": "cred:termsOfUse", "@type": "@id"},
                    "validFrom": {"@id": "cred:validFrom", "@type": "xsd:dateTime"},
                    "validUntil": {"@id": "cred:validUntil", "@type": "xsd:dateTime"}
                }
            },
            "VerifiablePresentation": {
                "@id": "https://www.w3.org/2018/credentials#VerifiablePresentation",
                "@context": {
                    "@version": 1.1,
                    "@protected": True,
                    "id": "@id",
                    "type": "@type",
                    "cred": "https://www.w3.org/2018/credentials#",
                    "sec": "https://w3id.org/security#",
                    "holder": {"@id": "cred:holder", "@type": "@id"},
                    "proof": {"@id": "sec:proof", "@type": "@id", "@container": "@graph"},
                    "verifiableCredential": {"@id": "cred:verifiableCredential", "@type": "@id", "@container": "@graph"}
                }
            },
            "EcdsaSecp256k1Signature2019": {
                "@id": "https://w3id.org/security#EcdsaSecp256k1Signature2019",
                "@context": {
                    "@version": 1.1,
                    "@protected": True,
                    "id": "@id",
                    "type": "@type",
                    "sec": "https://w3id.org/security#",
                    "xsd": "http://www.w3.org/2001/XMLSchema#",
                    "challenge": "sec:challenge",
                    "created": {"@id": "http://purl.org/dc/terms/created", "@type": "xsd:dateTime"},
                    "domain": "sec:domain",
                    "expires": {"@id": "sec:expiration", "@type": "xsd:dateTime"},
                    "jws": "sec:jws",
                    "nonce": "sec:nonce",
                    "proofPurpose": {
                        "@id": "sec:proofPurpose",
                        "@type": "@vocab",
                        "@context": {
                            "@version": 1.1,
                            "@protected": True,
                            "id": "@id",
                            "type": "@type",
                            "sec": "https://w3id.org/security#",
                            "assertionMethod": {"@id": "sec:assertionMethod", "@type": "@id", "@container": "@set"},
                            "authentication": {"@id": "sec:authenticationMethod", "@type": "@id", "@container": "@set"}
                        }
                    },
                    "proofValue": "sec:proofValue",
                    "verificationMethod": {"@id": "sec:verificationMethod", "@type": "@id"}
                }
            },
            "Ed25519Signature2020": {
                "@id": "https://w3id.org/security#Ed25519Signature2020",
                "@context": {
                    "@version": 1.1,
                    "@protected": True,
                    "id": "@id",
                    "type": "@type",
                    "sec": "https://w3id.org/security#",
                    "xsd": "http://www.w3.org/2001/XMLSchema#",
                    "challenge": "sec:challenge",
                    "created": {"@id": "http://purl.org/dc/terms/created", "@type": "xsd:dateTime"},
                    "domain": "sec:domain",
                    "expires": {"@id": "sec:expiration", "@type": "xsd:dateTime"},
                    "nonce": "sec:nonce",
                    "proofPurpose": {
                        "@id": "sec:proofPurpose",
                        "@type": "@vocab",
                        "@context": {
                            "@version": 1.1,
                            "@protected": True,
                            "id": "@id",
                            "type": "@type",
                            "sec": "https://w3id.org/security#",
                            "assertionMethod": {"@id": "sec:assertionMethod", "@type": "@id", "@container": "@set"},
                            "authentication": {"@id": "sec:authenticationMethod", "@type": "@id", "@container": "@set"}
                        }
                    },
                    "proofValue": "sec:proofValue",
                    "verificationMethod": {"@id": "sec:verificationMethod", "@type": "@id"}
                }
            }
        }
    },
    
    # Security Ed25519 2020 Context
    "https://w3id.org/security/suites/ed25519-2020/v1": {
        "@context": {
            "@protected": True,
            "id": "@id",
            "type": "@type",
            "sec": "https://w3id.org/security#",
            "xsd": "http://www.w3.org/2001/XMLSchema#",
            "Ed25519VerificationKey2020": {
                "@id": "https://w3id.org/security#Ed25519VerificationKey2020",
                "@context": {
                    "@protected": True,
                    "id": "@id",
                    "type": "@type",
                    "controller": {"@id": "sec:controller", "@type": "@id"},
                    "revoked": {"@id": "sec:revoked", "@type": "xsd:dateTime"},
                    "publicKeyMultibase": {"@id": "sec:publicKeyMultibase"}
                }
            },
            "Ed25519Signature2020": {
                "@id": "https://w3id.org/security#Ed25519Signature2020",
                "@context": {
                    "@protected": True,
                    "id": "@id",
                    "type": "@type",
                    "challenge": "sec:challenge",
                    "created": {"@id": "http://purl.org/dc/terms/created", "@type": "xsd:dateTime"},
                    "domain": "sec:domain",
                    "expires": {"@id": "sec:expiration", "@type": "xsd:dateTime"},
                    "nonce": "sec:nonce",
                    "proofPurpose": {
                        "@id": "sec:proofPurpose",
                        "@type": "@vocab",
                        "@context": {
                            "@protected": True,
                            "id": "@id",
                            "type": "@type",
                            "sec": "https://w3id.org/security#",
                            "assertionMethod": {"@id": "sec:assertionMethod", "@type": "@id", "@container": "@set"},
                            "authentication": {"@id": "sec:authenticationMethod", "@type": "@id", "@container": "@set"}
                        }
                    },
                    "proofValue": "sec:proofValue",
                    "verificationMethod": {"@id": "sec:verificationMethod", "@type": "@id"}
                }
            }
        }
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
            return {
                'contextUrl': None,
                'documentUrl': url,
                'document': CONTEXTS[url]
            }
        
        logger.warning(
            f"Context {url} not found in bundled contexts. "
            f"Attempting to load from network using default loader. "
            f"This may fail in restricted network environments."
        )
        
        try:
            options = kwargs.get('options', {}) 
            return jsonld.load_document(url, options=options)
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