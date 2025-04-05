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
    perform_self_test
)
from .exceptions import (
    VelaError,
    MissingParameterError,
    InvalidParameterError,
    SchemaValidationError,
    SigningError,
    VerificationError,
    DidGenerationError,
    CredentialError,
    CredentialFormatError,
    CredentialParseError,
    PresentationError,
    PresentationFormatError,
    ProductionGuardError,
    SelfTestError,
    SecretRetrievalError
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
from .secrets_handler import get_secret_name, retrieve_agent_private_key

# Define additional error types that aren't in errors.py
class ContentVerificationError(VelaError):
    """Error raised when content verification fails."""
    def __init__(self, message, details=None):
        super().__init__(message)
        self.details = details
        
    def to_dict(self):
        result = {
            "status": "error",
            "error": {
                "code": 1100,
                "message": str(self)
            }
        }
        if self.details:
            result["error"]["details"] = self.details
        return result

class UnknownOperationError(VelaError):
    """Error raised when an unknown operation is requested."""
    def __init__(self, operation, valid_operations):
        super().__init__(f"Unknown operation: {operation}. Valid operations: {', '.join(valid_operations)}")
        self.operation = operation
        self.valid_operations = valid_operations
        
    def to_dict(self):
        return {
            "status": "error",
            "error": {
                "code": 1001,
                "message": str(self),
                "requested_operation": self.operation,
                "valid_operations": self.valid_operations
            }
        }

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("vela-did-tool")

# Valid operations
VALID_OPERATIONS = ["generate", "sign", "sign_composite", "verify", "status", "self_test"]

class VelaDidToolRunner:
    """
    Main class for the Vela DID Tool.
    
    This class encapsulates the core operations of the tool and follows
    the pattern used by other Naptha tool modules.
    """
    
    def __init__(self, config: ToolConfig):
        """Initialize the tool runner with configuration."""
        self.config = config
        
    async def run(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run the appropriate operation based on the input parameters.
        
        Args:
            params: Dictionary of input parameters
            
        Returns:
            Dictionary with operation results or error
        """
        try:
            # Validate operation parameter
            try:
                operation = validate_string(
                    params, 
                    "operation", 
                    required=True,
                    min_length=1
                ).lower()
                
                if operation not in VALID_OPERATIONS:
                    error = UnknownOperationError(operation, VALID_OPERATIONS)
                    return error.to_dict()
                    
            except MissingParameterError as e:
                logger.error(f"Missing operation parameter: {e}")
                return {
                    "status": "error",
                    "error": f"Missing required parameter '{e.parameter_name}'"
                }
                
            except (InvalidParameterError, UnknownOperationError) as e:
                logger.error(f"Invalid operation: {e}")
                return {
                    "status": "error",
                    "error": str(e)
                }
            
            logger.info(f"Operation requested: {operation}")
            
            # Execute the requested operation
            if operation == "generate":
                return await self.handle_generate(params)
            elif operation == "sign":
                return await self.handle_sign(params)
            elif operation == "sign_composite":
                return await self.handle_sign_composite(params)
            elif operation == "verify":
                return await self.handle_verify(params)
            elif operation == "status":
                return await self.handle_status(params)
            elif operation == "self_test":
                return await self.handle_self_test(params)
                
        except VelaError as e:
            # Handle known errors with proper error codes
            logger.error(f"{type(e).__name__}: {e}")
            return {
                "status": "error",
                "error": str(e)
            }
            
        except Exception as e:
            # Handle unexpected errors
            error_msg = f"Unexpected error: {str(e)}"
            logger.error(error_msg)
            traceback.print_exc()
            
            return {
                "status": "error",
                "error": error_msg
            }
    
    async def handle_generate(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a new DID for an agent and output the agent's DID, verification method, 
        and private key in JWK format.
        
        Args:
            params: Input parameters
        
        Returns:
            Dictionary with the generated DID, verification method, and private key
        """
        # First, run the self-test to ensure the DID components are working correctly
        await perform_self_test()
        
        # Generate a new DID
        logger.info("Generating new DID and key")
        agent_did, verification_method, private_key_jwk = await generate_did()
        
        # Log successful generation (without including the private key)
        logger.info(f"Successfully generated DID: {agent_did}")
        logger.info(f"Verification method: {verification_method}")
        
        # Return the DID, verification method and private key
        # The private key should only be used for initial deployment!
        return {
            "status": "success",
            "result": {
                "agent_did": agent_did,
                "verification_method": verification_method,
                "private_key_jwk": private_key_jwk,
                "secret_name": get_secret_name(agent_did),
                "instructions": (
                    "IMPORTANT: Deploy this private key as a Naptha secret using: "
                    f"naptha deploy-secrets '{get_secret_name(agent_did)}' '<private-key-jwk>' -m vela-did-tool"
                )
            }
        }
    
    async def handle_sign(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sign a message using the agent's DID, creating a verifiable credential.
        
        Args:
            params: Input parameters
        
        Returns:
            Dictionary with the signed credential
        """
        try:
            # Get required parameters
            agent_did = validate_string(params, "agent-did", required=True)
            self._validate_did_format(agent_did)
            
            message = validate_string(params, "message", required=True)
            
            subject_did = params.get("subject-did", agent_did)
            if subject_did:
                self._validate_did_format(subject_did)
            
            # Get the configuration for the credential
            types = self.config.get_credential_types()
            contexts = self.config.get_contexts()
            expiration_days = self.config.get_expiration_days()
            
            # Log the signing operation
            logger.info(f"Signing message from {agent_did} to {subject_did}")
            logger.debug(f"Message: {message[:50]}...")
            logger.debug(f"Using credential types: {types}")
            logger.debug(f"Using credential contexts: {contexts}")
            logger.debug(f"Credential expires in {expiration_days} days")
            
            # Check if a private key was passed directly (for testing)
            private_key_jwk = validate_jwk(params, "private_key_jwk", required=False)
            
            # If no private key was passed, retrieve from Naptha secrets
            if not private_key_jwk:
                private_key_jwk = await retrieve_agent_private_key(agent_did)
            
            # Sign the message
            signed_credential = await sign(
                issuer_did=agent_did,
                subject_did=subject_did,
                message=message,
                private_key_jwk=private_key_jwk,
                types=types,
                contexts=contexts,
                expiration_days=expiration_days
            )
            
            # Return the signed credential
            return {
                "status": "success",
                "result": {
                    "signed_credential": signed_credential
                }
            }
        except (MissingParameterError, InvalidParameterError) as e:
            logger.error(f"Parameter error: {e}")
            raise
        except Exception as e:
            logger.error(f"Error while signing: {e}")
            raise SigningError(str(e))
    
    def _validate_did_format(self, did_str: str) -> None:
        """
        Validate that a string is a properly formatted DID.
        
        Args:
            did_str: The DID string to validate
            
        Raises:
            InvalidParameterError: If the DID format is invalid
        """
        # Basic DID pattern: did:method:specific-id
        did_pattern = r'^did:[a-z]+:.+$'
        import re
        if not re.match(did_pattern, did_str):
            raise InvalidParameterError("DID", f"Invalid DID format: {did_str}")
    
    async def handle_sign_composite(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sign a composite message (multiple fields) using the agent's DID, 
        creating a verifiable credential.
        
        Args:
            params: Input parameters
        
        Returns:
            Dictionary with the signed credential
        """
        try:
            # Get required parameters
            agent_did = validate_string(params, "agent-did", required=True)
            self._validate_did_format(agent_did)
            
            # Get message fields
            message_fields = {}
            for key, value in params.items():
                if key.startswith("field-"):
                    field_name = key[6:]  # Remove 'field-' prefix
                    message_fields[field_name] = value
            
            if not message_fields:
                raise MissingParameterError("field-*")
                
            subject_did = params.get("subject-did", agent_did)
            if subject_did:
                self._validate_did_format(subject_did)
            
            # Get the configuration for the credential
            types = self.config.get_credential_types()
            contexts = self.config.get_contexts()
            expiration_days = self.config.get_expiration_days()
            
            # Log the signing operation
            logger.info(f"Signing composite message from {agent_did} to {subject_did}")
            logger.debug(f"Message fields: {list(message_fields.keys())}")
            logger.debug(f"Using credential types: {types}")
            logger.debug(f"Using credential contexts: {contexts}")
            logger.debug(f"Credential expires in {expiration_days} days")
            
            # Check if a private key was passed directly (for testing)
            private_key_jwk = validate_jwk(params, "private-key-jwk", required=False)
            
            # If no private key was passed, retrieve from Naptha secrets
            if not private_key_jwk:
                private_key_jwk = await retrieve_agent_private_key(agent_did)
            
            # Sign the composite message
            signed_credential = await sign_composite(
                issuer_did=agent_did,
                subject_did=subject_did,
                message_fields=message_fields,
                private_key_jwk=private_key_jwk,
                types=types,
                contexts=contexts,
                expiration_days=expiration_days
            )
            
            # Return the signed credential
            return {
                "status": "success",
                "result": {
                    "signed_credential": signed_credential
                }
            }
        except (MissingParameterError, InvalidParameterError) as e:
            logger.error(f"Parameter error: {e}")
            raise
        except Exception as e:
            logger.error(f"Error while signing composite message: {e}")
            raise SigningError(str(e))
    
    async def handle_verify(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Verify a signed credential and optionally check its content.
        
        Args:
            params: Input parameters
        
        Returns:
            Dictionary with verification result
        """
        try:
            # Get required parameters
            signed_credential = validate_string(params, "signed-credential", required=True)
            
            # Optional parameters
            expected_message = params.get("expected-message")
            expected_subject = params.get("expected-subject")
            
            # Log the verification operation
            logger.info("Verifying signed credential")
            
            # Verify the credential
            verify_result = await verify(signed_credential)
            
            # Extract the message and check against expected message
            content_valid = True
            content_details = {}
            
            if expected_message is not None:
                try:
                    # Extract the message from the credential
                    actual_message = extract_message_from_credential(signed_credential)
                    
                    # Check if it matches the expected message
                    message_match = actual_message == expected_message
                    logger.info(f"Message validation: {'✓' if message_match else '✗'}")
                    content_details["message_match"] = message_match
                    content_valid = content_valid and message_match
                    
                    if not message_match:
                        content_details["expected_message"] = expected_message
                        content_details["actual_message"] = actual_message
                        
                except Exception as e:
                    logger.error(f"Error extracting message: {e}")
                    content_details["message_error"] = str(e)
                    content_valid = False
            
            if expected_subject is not None:
                try:
                    # Extract the subject DID from the credential
                    actual_subject = get_subject_did_from_credential(signed_credential)
                    
                    # Check if it matches the expected subject
                    subject_match = actual_subject == expected_subject
                    logger.info(f"Subject validation: {'✓' if subject_match else '✗'}")
                    content_details["subject_match"] = subject_match
                    content_valid = content_valid and subject_match
                    
                    if not subject_match:
                        content_details["expected_subject"] = expected_subject
                        content_details["actual_subject"] = actual_subject
                        
                except Exception as e:
                    logger.error(f"Error extracting subject: {e}")
                    content_details["subject_error"] = str(e)
                    content_valid = False
            
            # Return the verification result
            result = {
                "status": "success",
                "result": {
                    "valid": verify_result["valid"],
                    "details": verify_result,
                    "content_valid": content_valid
                }
            }
            
            if content_details:
                result["result"]["content_details"] = content_details
                
            return result
            
        except (MissingParameterError, InvalidParameterError) as e:
            logger.error(f"Parameter error: {e}")
            raise
        except Exception as e:
            logger.error(f"Error while verifying: {e}")
            raise VerificationError(str(e))
    
    async def handle_status(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get the current status of the tool, including production mode and
        cryptographic backend details.
        
        Args:
            params: Input parameters
        
        Returns:
            Dictionary with status information
        """
        try:
            # Initialize status result
            import didkit
            
            status_result = {
                "production_mode": PRODUCTION_MODE,
                "didkit_version": getattr(didkit, "version", lambda: "unknown")()
            }
            
            # Run a self-test if requested or in production mode
            try:
                self_test_result = await perform_self_test()
                status_result["self_test"] = {
                    "success": True,
                    "result": self_test_result
                }
            except Exception as e:
                status_result["self_test"] = {
                    "success": False,
                    "error": str(e)
                }
                
            return {
                "status": "success",
                "result": status_result
            }
        except Exception as e:
            logger.error(f"Error getting status: {e}")
            return {
                "status": "error",
                "error": str(e)
            }
    
    async def handle_self_test(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform a self-test to verify the tool is functioning correctly.
        
        Args:
            params: Input parameters
        
        Returns:
            Dictionary with self-test results
        """
        try:
            # Run the self-test
            logger.info("Running self-test")
            result = await perform_self_test()
            
            # Return the result
            return {
                "status": "success",
                "result": {
                    "success": True,
                    "didkit_test": result
                }
            }
        except Exception as e:
            logger.error(f"Self-test failed: {e}")
            return {
                "status": "error",
                "error": f"Self-test failed: {str(e)}"
            }

def parse_input_parameters() -> Dict[str, Any]:
    """
    Parse input parameters from stdin JSON, falling back to environment variables.
    
    Based on Naptha's parameter passing mechanism, the primary source of 
    parameters is JSON input via stdin. Environment variables with INPUT_
    prefix are supported as a fallback.
    
    Returns:
        Dictionary of parsed parameters
    """
    params = {}
    
    # Primary source: stdin JSON
    try:
        if not sys.stdin.isatty():
            logger.debug("Reading input from stdin")
            stdin_data = sys.stdin.read().strip()
            if stdin_data:
                stdin_params = json.loads(stdin_data)
                logger.debug(f"Parsed input parameters from stdin: {len(stdin_params)} parameters")
                params.update(stdin_params)
                return params  # Return early if we have stdin params
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON from stdin: {e}")
    except Exception as e:
        logger.error(f"Error reading from stdin: {e}")
    
    # Fallback: environment variables with INPUT_ prefix
    logger.debug("Checking environment variables with INPUT_ prefix")
    env_params = {}
    for key, value in os.environ.items():
        if key.startswith("INPUT_"):
            param_key = key[6:].lower().replace('_', '-')  # Convert INPUT_FOO_BAR to foo-bar
            env_params[param_key] = value
    
    if env_params:
        logger.debug(f"Found {len(env_params)} parameters from environment variables")
        params.update(env_params)
    
    logger.debug(f"Final parameters: {json.dumps(params)}")
    return params

async def main_async(params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Main asynchronous function to handle the Naptha Tool operations.
    
    This is the main entry point that Naptha will use when calling this module.
    
    Args:
        params: Dictionary of input parameters from Naptha (optional)
    
    Returns:
        Dict[str, Any]: A dictionary containing the operation result or error
    """
    try:
        # If params are not provided, parse them from stdin (Naptha's primary method)
        input_params = params if params is not None else parse_input_parameters()
        
        # Log the parameters we received (sanitized for security)
        log_params = {k: v for k, v in input_params.items() if not any(x in k.lower() for x in ["key", "secret", "token", "password"])}
        logger.debug(f"Running with parameters: {json.dumps(log_params)}")
        
        # Create tool configuration
        config = ToolConfig.from_input(input_params)
        
        # Create and run the tool
        tool = VelaDidToolRunner(config)
        return await tool.run(input_params)
            
    except VelaError as e:
        # Handle known errors with proper error codes
        logger.error(f"{type(e).__name__}: {e}")
        return {
            "status": "error",
            "error": str(e)
        }
        
    except Exception as e:
        # Handle unexpected errors
        error_msg = f"Unexpected error: {str(e)}"
        logger.error(error_msg)
        traceback.print_exc()
        
        return {
            "status": "error",
            "error": error_msg
        }

def main():
    """
    Entry point for the module when run directly.
    
    This function is called when the module is run as a script.
    When deployed as a Naptha Tool Module, Naptha will invoke main_async
    with parameters provided via stdin JSON.
    """
    # Run the async function with no params - it will parse from stdin
    result = asyncio.run(main_async())
    
    # Print the result as JSON
    print(json.dumps(result), flush=True)
    
    # Exit with appropriate code based on result status
    if result.get("status") == "error":
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    # This block is only executed when running the file directly for local testing.
    # When run by Naptha, the main_async function is called directly.
    main() 