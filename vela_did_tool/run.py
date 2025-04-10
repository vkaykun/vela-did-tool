#!/usr/bin/env python3
"""Main entry point for the DID/VC utility tool."""

import argparse
import json
import logging
import sys
from typing import Dict, Any, Optional, List, Tuple, Union
import os

from .did_utils import generate_did_key_ed25519, resolve_did, get_private_jwk_from_env
from .vc_utils import sign_credential_jsonld, verify_credential_jsonld, sign_credential_jwt, verify_credential_jwt
from .errors import VcError, DidError, InvalidKeyFormatError, KeyNotFoundError
from .schemas import InputSchema, VerificationMethod
from .constants import (
    DEFAULT_PROOF_TYPE,
    MULTIBASE_BASE58BTC_PREFIX,
)

logger = logging.getLogger(__name__)

def setup_logging(verbose: bool = False) -> None:
    """Configure logging for the application."""
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="DID/VC Utility Tool")
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    
    subparsers = parser.add_subparsers(dest='command', required=True, help='Command to execute')
    
    gen_parser = subparsers.add_parser('generate', help='Generate a new DID')
    gen_parser.add_argument('--key-type', choices=['ed25519'], default='ed25519',
                            help='Key type to use for DID generation')
    gen_parser.add_argument('--output', '-o', help='Output file for writing DID document and keys')
    
    resolve_parser = subparsers.add_parser('resolve', help='Resolve a DID to its document')
    resolve_parser.add_argument('did', help='DID to resolve')
    
    sign_parser = subparsers.add_parser('sign', help='Sign a verifiable credential')
    sign_group = sign_parser.add_mutually_exclusive_group(required=True)
    sign_group.add_argument('--key', help='File containing private key (JWK)')
    sign_group.add_argument('--agent-did', help='DID to use for key retrieval from environment')
    sign_parser.add_argument('--format', choices=['jsonld', 'jwt'], default='jsonld',
                         help='Format to use for signing')
    sign_parser.add_argument('--credential', required=True, 
                         help='File containing the credential to sign')
    sign_parser.add_argument('--issuer-did', help='DID of the issuer (if different from agent-did)')
    sign_parser.add_argument('--output', '-o', help='Output file for the signed credential')
    
    verify_parser = subparsers.add_parser('verify', help='Verify a signed credential')
    verify_parser.add_argument('--format', choices=['jsonld', 'jwt'], default='jsonld',
                            help='Format of the credential to verify')
    verify_parser.add_argument('credential', help='File containing the signed credential to verify')
    
    return parser.parse_args()


def load_json_file(file_path: str) -> Dict[str, Any]:
    """Load and parse a JSON file."""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        logger.error(f"Failed to load JSON from {file_path}: {e}")
        raise VcError(f"Failed to load JSON from {file_path}: {e}")


def write_json_file(data: Dict[str, Any], file_path: str) -> None:
    """Write data to a JSON file."""
    try:
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2)
        logger.info(f"Data written to {file_path}")
    except Exception as e:
        logger.error(f"Failed to write to {file_path}: {e}")
        raise VcError(f"Failed to write to {file_path}: {e}")


def handle_generate_did():
    """Generate a new DID key."""
    try:
        did_str, verification_method, private_jwk = generate_did_key_ed25519()
        
        if isinstance(verification_method, dict):
            public_key = verification_method
        elif hasattr(verification_method, "__dict__"):
            public_key = verification_method.__dict__
        else:
            public_key = {
                "id": verification_method.id,
                "type": verification_method.type,
                "controller": verification_method.controller,
                "publicKeyMultibase": verification_method.publicKeyMultibase
            }
        
        return {
            "did": did_str,
            "publicKey": public_key,
            "privateKey": private_jwk
        }
    except Exception as e:
        logger.error(f"Error generating DID: {e}")
        raise DidError(f"Failed to generate DID: {e}")


def resolve_did_document(did: str) -> Dict[str, Any]:
    """Resolve a DID to its DID Document."""
    try:
        document = resolve_did(did)
        return document
    except DidError as e:
        logger.error(f"Failed to resolve DID {did}: {e}")
        raise VcError(f"DID resolution failed: {e}")


def sign_credential(
    format: str,
    credential_input: Union[str, Dict[str, Any]],
    agent_did: Optional[str] = None,
    key_file: Optional[str] = None,
    issuer_did: Optional[str] = None,
    output_file: Optional[str] = None
) -> Dict[str, Any]:
    """Sign a verifiable credential in either JSON-LD or JWT format."""
    try:
        if agent_did:
            try:
                private_jwk = get_private_jwk_from_env(agent_did)
                if not issuer_did:
                    issuer_did = agent_did
            except KeyNotFoundError as e:
                raise VcError(f"Failed to retrieve private key for agent DID: {e}")
        elif key_file:
            private_jwk = load_json_file(key_file)
        else:
            raise VcError("Missing both 'agent_did' (env-based key) and 'key' (file path).")
        
        if isinstance(credential_input, str):
            credential = load_json_file(credential_input)
        elif isinstance(credential_input, dict):
            credential = credential_input
        else:
            raise VcError("Invalid 'credential' input type. Expected file path (str) or object (dict).")
        
        if format == 'jsonld':
            if not issuer_did and 'issuer' in credential:
                if isinstance(credential['issuer'], str):
                    issuer_did = credential['issuer']
                elif isinstance(credential['issuer'], dict) and 'id' in credential['issuer']:
                    issuer_did = credential['issuer']['id']
            
            if not issuer_did:
                raise VcError("Issuer DID is required for signing. Provide 'agent_did', 'issuer_did', or ensure 'issuer' in credential.")
            
            proof_options = {
                "verificationMethod": f"{issuer_did}#keys-1",
            }
            
            signed_credential = sign_credential_jsonld(credential, private_jwk, proof_options)
        
        elif format == 'jwt':
            if not issuer_did:
                raise VcError("Issuer DID ('agent_did' or 'issuer_did') is required for JWT signing.")
            
            jwt_payload = {
                "iss": issuer_did,  
                "vc": credential,  
            }
            
            jwt_string = sign_credential_jwt(jwt_payload, issuer_did, private_jwk)
            signed_credential = {"jwt": jwt_string}
        
        else:
            raise VcError(f"Unsupported format: {format}. Use 'jsonld' or 'jwt'.")
        
        if output_file:
            write_json_file(signed_credential, output_file)
            
        return signed_credential
            
    except (VcError, InvalidKeyFormatError, KeyNotFoundError) as e:
        raise
    except Exception as e:
        logger.exception(f"Failed to sign credential in {format} format")
        raise VcError(f"Signing failed: {e}")


def verify_credential(
    format: str,
    credential_input: Union[str, Dict[str, Any]]
) -> Dict[str, Any]:
    """Verifies a credential in the specified format.
    
    Args:
        format: Either 'jsonld' or 'jwt'
        credential_input: Can be a file path (string) containing the credential,
                          or a credential object (dict) for JSON-LD.
                          
    Returns:
        A verification result including verified status, issuer, and any errors.
    """
    try:
        # First, detect if this is a JWT string directly
        if format == 'jwt' and isinstance(credential_input, str) and credential_input.count('.') == 2 and credential_input.startswith('eyJ'):
            logger.debug("Detected JWT format string directly in input, using as-is")
            credential_data = credential_input.strip()
        # Otherwise, process as before
        elif isinstance(credential_input, str):
            if format == 'jsonld':
                # Check if this is actually a JSON string or a file path
                if credential_input.lstrip().startswith('{'):
                    try:
                        # Try to parse as direct JSON string
                        credential_data = json.loads(credential_input)
                        logger.debug("Parsed credential_input as direct JSON string")
                    except json.JSONDecodeError:
                        # Not valid JSON, treat as file path
                        logger.debug("Treating credential_input as file path")
                        credential_data = load_json_file(credential_input)
                else:
                    # Not starting with '{', assume file path
                    logger.debug("Treating credential_input as file path")
                    credential_data = load_json_file(credential_input)
            elif format == 'jwt':
                # For JWT, just use the string as-is (already handled by direct JWT check above)
                # This is a fallback for other JWT strings that don't match the eyJ pattern
                logger.debug("Processing JWT input string")
                credential_data = credential_input.strip()
            else:
                raise VcError(f"Unsupported format for file input: {format}")
        elif isinstance(credential_input, dict):
            if format != 'jsonld':
                # If format is JWT but input is dict, check if there's a jwt field
                if format == 'jwt' and 'jwt' in credential_input:
                    logger.debug("Extracting JWT from credential_input dictionary")
                    credential_data = credential_input['jwt'].strip()
                else:
                    raise VcError(f"Received credential object but format is '{format}'. Expected JSON-LD.")
            else:
                credential_data = credential_input
        else:
            raise VcError("Invalid 'credential' input type. Expected file path (str) or object (dict).")
            
        if format == 'jsonld':
            logger.debug("Verifying JSON-LD credential")
            verified, issuer_did, error_msg = verify_credential_jsonld(credential_data)
            
            result = {
                "verified": verified,
                "issuer": issuer_did if verified else None
            }
            if error_msg:
                result["error"] = error_msg
                
        elif format == 'jwt':
            logger.debug(f"Verifying JWT credential: {credential_data[:30]}...")
            verified, issuer_did, payload, error_msg = verify_credential_jwt(credential_data)
            
            result = {
                "verified": verified,
                "issuer": issuer_did if verified else None,
                "payload": payload if verified else None
            }
            if error_msg:
                result["error"] = error_msg
                
        else:
            raise VcError(f"Unsupported format: {format}. Use 'jsonld' or 'jwt'.")
        
        return result
        
    except Exception as e:
        logger.exception(f"Failed to verify credential in {format} format")
        raise VcError(f"Verification failed: {e}")

def run(*args, **kwargs) -> Dict[str, Any]:
    """
    Process a command based on arguments passed by the Naptha worker.
    
    Args:
        *args: Positional arguments (likely unused by Naptha worker).
        **kwargs: Keyword arguments passed by the Naptha worker. 
                  We expect the original inputs to be nested within kwargs,
                  potentially under a key like 'module_run'.
        
    Returns:
        Dict containing the result of the operation
    
    Raises:
        VcError: If execution fails or required inputs are missing.
    """
    logger.info(f"EXECUTING VELA-DID-TOOL")
    
    logger.debug(f"Received args: {args}")
    logger.debug(f"Received kwargs: {kwargs}")
    
    input_payload = None
    
    if 'func_name' in kwargs and 'func_input_data' in kwargs:
        input_payload = kwargs 
        logger.debug("Found inputs directly in kwargs")
        
    elif 'module_run' in kwargs and isinstance(kwargs['module_run'], dict):
        module_run_dict = kwargs['module_run']
        if 'inputs' in module_run_dict and isinstance(module_run_dict['inputs'], dict):
             if 'func_name' in module_run_dict['inputs']:
                  input_payload = module_run_dict['inputs']
                  logger.debug("Found inputs nested under kwargs['module_run']['inputs']")

        elif 'func_name' in module_run_dict:
             input_payload = module_run_dict 
             logger.debug("Found inputs nested directly under kwargs['module_run']")

    elif args and len(args) > 0 and isinstance(args[0], dict) and 'func_name' in args[0]:
        input_payload = args[0]
        logger.debug("Found inputs as first positional arg (args[0])")

    if input_payload is None:
        raise VcError("Could not find required input payload ('func_name', 'func_input_data') in args or kwargs")

    func_name = input_payload.get('func_name')
    params = input_payload.get('func_input_data', {}) 

    if not func_name:
        raise VcError("Missing 'func_name' in input payload")
    if not isinstance(params, dict):
         raise VcError("'func_input_data' must be a dictionary")

    logger.info(f"Executing function: {func_name}")
    
    if func_name in ['generate', 'generate-did']:
        result = handle_generate_did()
        output_file = params.get('output')
        if output_file:
            write_json_file(result, output_file)
        return result
        
    elif func_name in ['resolve', 'resolve-did']:
        did = params.get('did')
        if not did:
            raise VcError("Missing 'did' parameter for resolve in func_input_data")
        return resolve_did_document(did)
        
    elif func_name == 'sign':
        format_val = params.get('format', params.get('credential_format', 'jsonld'))
        credential = params.get('credential')
        agent_did = params.get('agent_did')
        key_file = params.get('key')
        issuer_did = params.get('issuer_did')
        output_file = params.get('output')
        
        if not agent_did and not key_file:
            raise VcError("Missing both 'agent_did' and 'key' in func_input_data for sign")
        if not credential:
            raise VcError("Missing 'credential' in func_input_data for sign")
            
        return sign_credential(
            format=format_val,
            credential_input=credential,
            agent_did=agent_did,
            key_file=key_file,
            issuer_did=issuer_did,
            output_file=output_file
        )
        
    elif func_name == 'verify':
        format_val = params.get('format', params.get('credential_format', 'jsonld'))
        credential = params.get('credential')
        
        if not credential:
            raise VcError("Missing 'credential' in func_input_data for verify")
            
        return verify_credential(
            format=format_val, 
            credential_input=credential
        )
        
    else:
        raise VcError(f"Unknown function: {func_name}")


def main() -> int:
    """Command-line entry point."""
    try:
        args = parse_args()
        setup_logging(args.verbose)
        
        if args.command == 'generate':
            result = handle_generate_did()
            if args.output:
                write_json_file(result, args.output)
        
        elif args.command == 'resolve':
            result = resolve_did_document(args.did)
        
        elif args.command == 'sign':
            result = sign_credential(
                format=args.format,
                credential_input=args.credential,
                agent_did=args.agent_did,
                key_file=args.key,
                issuer_did=args.issuer_did,
                output_file=args.output
            )
        
        elif args.command == 'verify':
            result = verify_credential(
                format=args.format,
                credential_input=args.credential
            )
        
        else:
            print(f"Unknown command: {args.command}", file=sys.stderr)
            return 1
        
        print(json.dumps(result, indent=2))
        return 0
        
    except VcError as e:
        print(json.dumps({"error": str(e)}, indent=2))
        return 1
    except Exception as e:
        print(json.dumps({"error": f"Unexpected error: {e}"}, indent=2))
        logger.exception("Unexpected error occurred")
        return 1


if __name__ == "__main__":
    sys.exit(main())