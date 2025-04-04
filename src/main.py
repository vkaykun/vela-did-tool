"""
Entry point for the vela-did-tool Naptha Tool Module.
This module processes input parameters from Naptha and performs
DID generation, signing, or verification accordingly.
"""

import asyncio
import argparse
import json
import logging
import os
import sys
from typing import Dict, Any, Optional, List, Union, Tuple
import traceback

from .did_utils import (
    generate_did, 
    sign, 
    sign_composite,
    verify, 
    extract_message_from_credential,
    extract_composite_from_credential,
    get_subject_did_from_credential,
    get_wasm_integrity_status,
    is_using_mock,
    perform_self_test
)
from .exceptions import (
    VelaError,
    MissingParameterError,
    InvalidParameterError,
    SchemaValidationError,
    SigningError,
    VerificationError,
    DIDGenerationError,
    CredentialError,
    ContentVerificationError,
    WAsmIntegrityError,
    MockInProductionError,
    UnknownOperationError
)
from .validators import (
    validate_string,
    validate_integer,
    validate_did,
    validate_jwk,
    validate_credential,
    validate_verification_method,
    validate_credential_type
)
from .config import ToolConfig, AVAILABLE_CREDENTIAL_TYPES
from .production_guard import PRODUCTION_MODE, fail_in_production

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("vela-did-tool")

# Valid operations
VALID_OPERATIONS = ["generate", "sign", "sign_composite", "verify", "status", "self_test"]

async def main_async(input_params: Dict[str, Any]) -> None:
    """
    Main asynchronous function to handle the Naptha Tool operations.
    
    Args:
        input_params: Dictionary of input parameters from Naptha
    
    Returns:
        None
    """
    try:
        # Create tool configuration
        config = ToolConfig.from_input(input_params)
        
        # Check for mock implementations in production - fail fast if detected
        if PRODUCTION_MODE and is_using_mock():
            fail_in_production("Mock implementation detected in production mode")
        
        # Validate operation parameter
        try:
            operation = validate_string(
                input_params, 
                "operation", 
                required=True,
                min_length=1
            ).lower()
            
            if operation not in VALID_OPERATIONS:
                raise UnknownOperationError(operation, VALID_OPERATIONS)
                
        except MissingParameterError as e:
            logger.error(f"Missing operation parameter: {e}")
            print(json.dumps(e.to_dict()), flush=True)
            sys.exit(1)
            
        except (InvalidParameterError, UnknownOperationError) as e:
            logger.error(f"Invalid operation: {e}")
            print(json.dumps(e.to_dict()), flush=True)
            sys.exit(1)
        
        logger.info(f"Operation requested: {operation}")
        
        # Execute the requested operation
        output: Dict[str, Any] = {}

        if operation == "generate":
            output = await handle_generate(input_params, config)
        elif operation == "sign":
            output = await handle_sign(input_params, config)
        elif operation == "sign_composite":
            output = await handle_sign_composite(input_params, config)
        elif operation == "verify":
            output = await handle_verify(input_params, config)
        elif operation == "status":
            output = await handle_status(input_params, config)
        elif operation == "self_test":
            output = await handle_self_test(input_params, config)
        
        # Output result as JSON
        print(json.dumps(output), flush=True)
            
    except VelaError as e:
        # Handle known errors with proper error codes
        logger.error(f"{type(e).__name__}: {e}")
        print(json.dumps(e.to_dict()), flush=True)
        sys.exit(1)
        
    except Exception as e:
        # Handle unexpected errors
        error_msg = f"Unexpected error: {str(e)}"
        logger.error(error_msg)
        traceback.print_exc()
        
        error_response = {
            "status": "error",
            "error": {
                "code": 1999,  # Generic error code
                "message": error_msg
            }
        }
        print(json.dumps(error_response), flush=True)
        sys.exit(1)

async def handle_generate(params: Dict[str, Any], config: ToolConfig) -> Dict[str, Any]:
    """Generate a new DID and key pair"""
    logger.info("Handling generate operation")
    
    try:
        # Generate DID key pair
        jwk, did, verification_method = generate_did()
        
        return {
            "status": "success",
            "did": did,
            "verification_method": verification_method,
            "jwk": jwk,
            "using_mock": is_using_mock()
        }
    
    except Exception as e:
        logger.error(f"Error generating DID: {e}")
        raise DIDGenerationError(str(e))

async def handle_sign(params: Dict[str, Any], config: ToolConfig) -> Dict[str, Any]:
    """Sign a message with a private key (JWK) to create a verifiable credential"""
    logger.info("Handling sign operation")
    
    try:
        # Validate parameters
        jwk = validate_jwk(params, "jwk", required=True)
        message = validate_string(params, "message", required=True)
        
        # Optional parameters
        did = validate_did(params, "did", required=False)
        verification_method = validate_verification_method(params, "verification_method", required=False)
        
        # Optional credential parameters
        credential_types = validate_credential_type(
            params, 
            "credential_types",
            required=False,
            default_value=config.get_credential_types()
        )
        contexts = params.get("contexts", config.get_contexts())
        expiration_days = validate_integer(
            params, 
            "expiration_days", 
            required=False, 
            min_value=1, 
            max_value=3650,
            default_value=config.get_expiration_days()
        )
        
        # Sign the message
        signed_credential = sign(
            jwk=jwk,
            message=message,
            credential_types=credential_types,
            contexts=contexts,
            did=did,
            verification_method=verification_method,
            expiration_days=expiration_days
        )
        
        return {
            "status": "success",
            "signed_credential": signed_credential,
            "using_mock": is_using_mock(),
            "config": {
                "credential_types": credential_types,
                "contexts": contexts,
                "expiration_days": expiration_days
            }
        }
        
    except VelaError as e:
        # Re-raise any VelaErrors
        raise
    
    except Exception as e:
        logger.error(f"Error in sign operation: {e}")
        raise SigningError(str(e))

async def handle_sign_composite(params: Dict[str, Any], config: ToolConfig) -> Dict[str, Any]:
    """Sign composite data with a private key (JWK) to create a verifiable credential"""
    logger.info("Handling sign_composite operation")
    
    try:
        # Validate parameters
        jwk = validate_jwk(params, "jwk", required=True)
        composite = params.get("composite")
        if not composite:
            raise MissingParameterError("composite")
        
        # Optional parameters
        did = validate_did(params, "did", required=False)
        verification_method = validate_verification_method(params, "verification_method", required=False)
        
        # Optional credential parameters
        credential_types = validate_credential_type(
            params, 
            "credential_types",
            required=False,
            default_value=config.get_credential_types()
        )
        contexts = params.get("contexts", config.get_contexts())
        expiration_days = validate_integer(
            params, 
            "expiration_days", 
            required=False, 
            min_value=1, 
            max_value=3650,
            default_value=config.get_expiration_days()
        )
        
        # Sign the composite data
        signed_credential = sign_composite(
            jwk=jwk,
            composite=composite,
            credential_types=credential_types,
            contexts=contexts,
            did=did,
            verification_method=verification_method,
            expiration_days=expiration_days
        )
        
        return {
            "status": "success",
            "signed_credential": signed_credential,
            "using_mock": is_using_mock(),
            "config": {
                "credential_types": credential_types,
                "contexts": contexts,
                "expiration_days": expiration_days
            }
        }
        
    except VelaError as e:
        # Re-raise any VelaErrors
        raise
    
    except Exception as e:
        logger.error(f"Error in sign_composite operation: {e}")
        raise SigningError(str(e))

async def handle_verify(params: Dict[str, Any], config: ToolConfig) -> Dict[str, Any]:
    """Verify a signed credential and extract its message"""
    logger.info("Handling verify operation")
    
    try:
        # Validate parameters
        signed_credential = validate_credential(params, "signed_credential", required=True)
        
        # Verify the credential
        verify_result = verify(signed_credential)
        
        # If verification failed, raise a specific error
        if not verify_result["valid"]:
            raise VerificationError(
                f"Credential verification failed: {verify_result.get('details', 'Unknown error')}",
                verify_result
            )
        
        # Extract message or composite data
        try:
            message = extract_message_from_credential(signed_credential)
            data_type = "message"
            data = message
        except:
            try:
                composite = extract_composite_from_credential(signed_credential)
                data_type = "composite"
                data = composite
            except:
                data_type = "unknown"
                data = None
                
        # Extract subject DID if available
        try:
            subject_did = get_subject_did_from_credential(signed_credential)
        except:
            subject_did = None
            
        return {
            "status": "success",
            "valid": True,
            "data_type": data_type,
            "data": data,
            "subject_did": subject_did,
            "verification_details": verify_result,
            "using_mock": is_using_mock()
        }
        
    except VerificationError as e:
        # Return structured error with verification details
        return {
            "status": "error",
            "valid": False,
            "error": {
                "code": e.code,
                "message": str(e)
            },
            "verification_details": e.context,
            "using_mock": is_using_mock()
        }
    
    except VelaError as e:
        # Re-raise other VelaErrors
        raise
    
    except Exception as e:
        logger.error(f"Error in verify operation: {e}")
        raise VerificationError(str(e))

async def handle_status(params: Dict[str, Any], config: ToolConfig) -> Dict[str, Any]:
    """Return status information about the tool's DID implementation"""
    logger.info("Handling status operation")
    
    # Get WASM integrity status
    integrity_status = get_wasm_integrity_status()
    
    return {
        "status": "success",
        "wasm_status": {
            "integrity_verified": integrity_status["verified"],
            "integrity_message": integrity_status["message"],
            "using_mock": is_using_mock()
        },
        "production_mode": PRODUCTION_MODE,
        "supported_operations": VALID_OPERATIONS,
        "credential_config": config.to_dict()
    }

async def handle_self_test(params: Dict[str, Any], config: ToolConfig) -> Dict[str, Any]:
    """Perform a self-test of the DID implementation"""
    logger.info("Handling self_test operation")
    
    try:
        # Run the self-test
        test_result = perform_self_test()
        
        if not test_result["success"]:
            if PRODUCTION_MODE:
                fail_in_production(f"Self-test failed in production mode: {test_result['message']}")
            
            raise ContentVerificationError(
                f"Self-test failed: {test_result['message']}",
                test_result
            )
        
        return {
            "status": "success",
            "self_test": test_result,
            "using_mock": is_using_mock()
        }
        
    except VelaError as e:
        # Re-raise any VelaErrors
        raise
    
    except Exception as e:
        logger.error(f"Error in self_test operation: {e}")
        if PRODUCTION_MODE:
            fail_in_production(f"Self-test failed with error: {str(e)}")
        raise ContentVerificationError(str(e))

def main():
    """
    Main entry point for the vela-did-tool.
    Parses parameters from command line or stdin and calls the main_async function.
    """
    params = {}
    
    # Check if there are command line arguments that might contain JSON
    if len(sys.argv) > 1:
        try:
            # Try to parse the first argument as JSON
            params = json.loads(sys.argv[1])
            logger.info("Loaded parameters from command line argument")
        except json.JSONDecodeError:
            # If first argument isn't JSON, check if it's a file path
            if os.path.isfile(sys.argv[1]):
                try:
                    with open(sys.argv[1], 'r') as f:
                        params = json.load(f)
                        logger.info(f"Loaded parameters from file: {sys.argv[1]}")
                except (json.JSONDecodeError, IOError) as e:
                    logger.warning(f"Failed to load parameters from file: {e}")
    
    # If no parameters from command line, try reading from stdin
    if not params:
        try:
            # Check if there's data available on stdin
            if not sys.stdin.isatty():
                stdin_data = sys.stdin.read().strip()
                if stdin_data:
                    params = json.loads(stdin_data)
                    logger.info("Loaded parameters from stdin")
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Failed to load parameters from stdin: {e}")
    
    # If still no parameters, use empty dict (operations will validate required params)
    if not params:
        logger.warning("No parameters found in command line or stdin, using empty dict")
        params = {}
    
    # Run the async main function
    asyncio.run(main_async(params))

if __name__ == "__main__":
    main() 