#!/usr/bin/env python3
import json
import os
import sys
import requests
import urllib.parse
from pyld import jsonld
from vela_did_tool.did_utils import get_private_jwk_from_env
from vela_did_tool.vc_utils import sign_credential_jsonld

def custom_document_loader(url, options={}):
    print(f"Loading document from: {url}")
    
    if url.startswith("https://w3id.org/security/suites/ed25519-2020/v1"):
        return {
            "contentType": "application/ld+json",
            "contextUrl": None,
            "document": {
                "@context": {
                    "@version": 1.1,
                    "id": "@id",
                    "type": "@type",
                    "Ed25519Signature2020": {
                        "@id": "https://w3id.org/security#Ed25519Signature2020",
                        "@context": {
                            "@version": 1.1,
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
            "documentUrl": url
        }
    
    try:
        response = requests.get(url)
        response.raise_for_status()
        
        content_type = response.headers.get('content-type', '').split(';')[0].strip()
        if content_type in ['application/json', 'application/ld+json']:
            return {
                "contentType": content_type,
                "contextUrl": None,
                "document": response.json(),
                "documentUrl": url
            }
        else:
            return {
                "contentType": content_type,
                "contextUrl": None,
                "document": response.text,
                "documentUrl": url
            }
    except Exception as e:
        print(f"Error loading document from {url}: {e}")
        raise jsonld.JsonLdError(
            'Loading remote context failed',
            'jsonld.InvalidUrl',
            code='loading remote context failed',
            url=url,
            cause=e
        )

jsonld.set_document_loader(custom_document_loader)

did = "did:key:z6MkvSXNVKQBvhzMVGo63ZLq3EABGcHxCu2tfmAxJFvs7b8e"
env_var_name = f"NAPTHA_SECRET_{did.replace(':', '_')}"
alt_env_var_name = f"NAPTHA_SECRET_{did.replace(':', '_')}"

print(f"Checking for environment variable: {env_var_name}")
if env_var_name not in os.environ:
    print(f"Warning: Environment variable {env_var_name} not found!")
    if alt_env_var_name in os.environ:
        print(f"Alternative environment variable {alt_env_var_name} found!")
    else:
        print(f"Error: No environment variable found for DID {did}. Cannot sign without private key.")
        sys.exit(1)

credential_path = "/Users/vkay/vela-did-tool/test_data/test_credential.json"
try:
    with open(credential_path, 'r') as f:
        credential = json.load(f)
    print(f"Loaded credential: {json.dumps(credential, indent=2)}")
except Exception as e:
    print(f"Error loading credential: {e}")
    sys.exit(1)

try:
    private_jwk = get_private_jwk_from_env(did)
    print("Successfully retrieved private JWK from environment")
except Exception as e:
    print(f"Error retrieving private key: {e}")
    sys.exit(1)

proof_options = {
    "verificationMethod": f"{did}#keys-1",
    "proofPurpose": "assertionMethod"
}

try:
    signed_credential = sign_credential_jsonld(credential, private_jwk, proof_options)
    
    output_path = "/Users/vkay/vela-did-tool/test_data/signed_credential.json"
    with open(output_path, 'w') as f:
        json.dump(signed_credential, f, indent=2)
    print(f"Successfully signed credential and saved to {output_path}")
    print(f"Signed credential: {json.dumps(signed_credential, indent=2)}")
except Exception as e:
    print(f"Error signing credential: {e}")
    traceback_info = sys.exc_info()[2]
    print(f"Traceback: {traceback_info.tb_frame.f_code.co_filename}:{traceback_info.tb_lineno}") 