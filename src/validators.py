"""
Parameter validation utilities for the vela-did-tool.
This module provides functions to validate input parameters and ensure they
meet the requirements for operations.
"""

import re
import json
from typing import Dict, Any, List, Optional, Union, Callable, TypeVar, cast

from .exceptions import (
    MissingParameterError,
    InvalidParameterError,
    SchemaValidationError,
    CredentialParseError,
    CredentialFormatError
)

# Type variable for generic validators
T = TypeVar('T')

def validate_required(params: Dict[str, Any], parameter: str) -> Any:
    """
    Validates that a required parameter exists and is not empty.
    
    Args:
        params: The parameters dictionary
        parameter: The name of the parameter to validate
        
    Returns:
        The parameter value if valid
        
    Raises:
        MissingParameterError: If the parameter is missing or empty
    """
    value = params.get(parameter)
    
    # Check if value exists and is not empty
    if value is None:
        raise MissingParameterError(parameter)
    
    # For string values, check if empty after stripping
    if isinstance(value, str) and not value.strip():
        raise MissingParameterError(
            parameter,
            f"Parameter '{parameter}' cannot be empty"
        )
    
    return value


def validate_optional(
    params: Dict[str, Any], 
    parameter: str, 
    default: Optional[T] = None
) -> Optional[T]:
    """
    Gets an optional parameter with a default value.
    
    Args:
        params: The parameters dictionary
        parameter: The name of the parameter to get
        default: Default value if parameter is missing
        
    Returns:
        The parameter value or default
    """
    value = params.get(parameter)
    
    # If value is None or an empty string, return default
    if value is None or (isinstance(value, str) and not value.strip()):
        return default
    
    return cast(T, value)


def validate_string(
    params: Dict[str, Any], 
    key: str, 
    required: bool = False,
    min_length: int = 0,
    max_length: Optional[int] = None,
    pattern: Optional[str] = None,
    choices: Optional[List[str]] = None
) -> str:
    """
    Validate that a parameter is a string and meets the specified constraints.
    
    Args:
        params: Dictionary containing parameters
        key: The key to validate
        required: Whether the parameter is required
        min_length: Minimum length of the string
        max_length: Maximum length of the string
        pattern: Regex pattern the string must match
        choices: List of valid values
        
    Returns:
        The validated string value
        
    Raises:
        MissingParameterError: If the parameter is required but missing
        InvalidParameterError: If the parameter fails validation
    """
    # Check if the parameter exists
    if key not in params:
        if required:
            raise MissingParameterError(key)
        return ""
    
    # Check if it's a string
    value = params[key]
    if not isinstance(value, str):
        raise InvalidParameterError(
            key, f"Expected string but got {type(value).__name__}"
        )
    
    # Check minimum length
    if min_length > 0 and len(value) < min_length:
        raise InvalidParameterError(
            key, f"String must be at least {min_length} characters long"
        )
    
    # Check maximum length
    if max_length is not None and len(value) > max_length:
        raise InvalidParameterError(
            key, f"String must be at most {max_length} characters long"
        )
    
    # Check pattern
    if pattern is not None and not re.match(pattern, value):
        raise InvalidParameterError(
            key, f"String must match pattern: {pattern}"
        )
    
    # Check if value is in allowed choices
    if choices is not None and value not in choices:
        raise InvalidParameterError(
            key, f"Value must be one of: {', '.join(choices)}"
        )
    
    return value


def validate_integer(
    params: Dict[str, Any], 
    key: str, 
    required: bool = False,
    min_value: Optional[int] = None,
    max_value: Optional[int] = None,
    default: Optional[int] = None,
    default_value: Optional[int] = None
) -> int:
    """
    Validate that a parameter is an integer and meets the specified constraints.
    
    Args:
        params: Dictionary containing parameters
        key: The key to validate
        required: Whether the parameter is required
        min_value: Minimum allowed value
        max_value: Maximum allowed value
        default: Default value if parameter is missing and not required
        default_value: Alternative parameter name for default value (for compatibility)
        
    Returns:
        The validated integer value
        
    Raises:
        MissingParameterError: If the parameter is required but missing
        InvalidParameterError: If the parameter fails validation
    """
    # Use default_value if provided, otherwise use default
    if default_value is not None:
        default = default_value
        
    # Check if the parameter exists
    if key not in params:
        if required:
            raise MissingParameterError(key)
        return default if default is not None else 0
    
    # Get the value and try to convert to int if it's a string
    value = params[key]
    if isinstance(value, str):
        try:
            value = int(value)
        except ValueError:
            raise InvalidParameterError(
                key, f"Could not convert string '{value}' to integer"
            )
    
    # Check if it's an integer
    if not isinstance(value, int):
        raise InvalidParameterError(
            key, f"Expected integer but got {type(value).__name__}"
        )
    
    # Check minimum value
    if min_value is not None and value < min_value:
        raise InvalidParameterError(
            key, f"Value must be at least {min_value}"
        )
    
    # Check maximum value
    if max_value is not None and value > max_value:
        raise InvalidParameterError(
            key, f"Value must be at most {max_value}"
        )
    
    return value


def validate_did(params: Dict[str, Any], key: str, required: bool = False, default_value: Optional[str] = None) -> str:
    """
    Validate that a parameter is a valid DID.
    
    Args:
        params: Dictionary containing parameters
        key: The key to validate
        required: Whether the parameter is required
        default_value: Default value to use if the parameter is missing
        
    Returns:
        The validated DID string
        
    Raises:
        MissingParameterError: If the parameter is required but missing
        InvalidParameterError: If the parameter is not a valid DID
    """
    # Basic DID pattern: did:method:specific-id
    did_pattern = r'^did:[a-z]+:.+$'
    
    # Check if parameter is missing and we have a default value
    if key not in params and default_value is not None:
        return default_value
    
    # Use the string validator with the DID pattern
    return validate_string(
        params, 
        key, 
        required=required,
        min_length=7,  # Minimum possible length for a valid DID (did:a:b)
        pattern=did_pattern
    )


def validate_jwk(params: Dict[str, Any], key: str, required: bool = False) -> Dict[str, Any]:
    """
    Validate that a parameter is a valid JWK (either as a string or dict).
    
    Args:
        params: Dictionary containing parameters
        key: The key to validate
        required: Whether the parameter is required
        
    Returns:
        The validated JWK as a dictionary
        
    Raises:
        MissingParameterError: If the parameter is required but missing
        InvalidParameterError: If the parameter is not a valid JWK
    """
    # Check if the parameter exists
    if key not in params:
        if required:
            raise MissingParameterError(key)
        return {}
    
    value = params[key]
    
    # If it's a string, try to parse it as JSON
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            raise InvalidParameterError(
                key, "JWK string is not valid JSON"
            )
    
    # Check if it's a dictionary
    if not isinstance(value, dict):
        raise InvalidParameterError(
            key, f"Expected JWK object but got {type(value).__name__}"
        )
    
    # Check required JWK fields
    if 'kty' not in value:
        raise InvalidParameterError(
            key, "JWK missing required 'kty' field"
        )
    
    # For specific key types, check additional required fields
    if value['kty'] == 'OKP':
        if 'crv' not in value:
            raise InvalidParameterError(
                key, "OKP JWK missing required 'crv' field"
            )
        if 'x' not in value:
            raise InvalidParameterError(
                key, "OKP JWK missing required 'x' field (public key)"
            )
    
    return value


def validate_credential(params: Dict[str, Any], key: str, required: bool = False) -> str:
    """
    Validate that a parameter is a valid Verifiable Credential JSON string.
    
    Args:
        params: Dictionary containing parameters
        key: The key to validate
        required: Whether the parameter is required
        
    Returns:
        The validated credential string
        
    Raises:
        MissingParameterError: If the parameter is required but missing
        InvalidParameterError: If the parameter is not a valid credential
    """
    # Get the string value
    credential_str = validate_string(
        params, 
        key, 
        required=required,
        min_length=2  # At least "{}" for a minimal JSON
    )
    
    if not credential_str:
        return credential_str
    
    # Check if it's a valid JSON
    try:
        credential = json.loads(credential_str)
    except json.JSONDecodeError:
        # If it starts with "ey", it might be a JWT
        if credential_str.startswith("ey") and "." in credential_str:
            # It appears to be a JWT - we'll let the actual verification code handle this
            return credential_str
        else:
            raise InvalidParameterError(
                key, "Credential is not valid JSON or JWT format"
            )
    
    # If it's a JSON object, check for minimal VC fields if not a JWT
    if isinstance(credential, dict):
        # For JWT-formatted credentials, we don't need to validate structure here
        # For JSON-LD credentials, check for minimal required fields
        if '@context' not in credential:
            raise InvalidParameterError(
                key, "Credential missing required '@context' field"
            )
        if 'type' not in credential:
            raise InvalidParameterError(
                key, "Credential missing required 'type' field"
            )
    
    return credential_str


def validate_verification_method(
    params: Dict[str, Any], 
    key: str, 
    required: bool = False
) -> str:
    """
    Validate that a parameter is a valid verification method DID URL.
    
    Args:
        params: Dictionary containing parameters
        key: The key to validate
        required: Whether the parameter is required
        
    Returns:
        The validated verification method string
        
    Raises:
        MissingParameterError: If the parameter is required but missing
        InvalidParameterError: If the parameter is not a valid verification method
    """
    # Verification method pattern: did:method:specific-id#fragment
    vm_pattern = r'^did:[a-z]+:.+#.+$'
    
    # Use the string validator with the verification method pattern
    return validate_string(
        params, 
        key, 
        required=required,
        min_length=9,  # Minimum possible length (did:a:b#c)
        pattern=vm_pattern
    )


def validate_credential_type(
    params: Dict[str, Any], 
    key: str, 
    required: bool = False,
    valid_types: Optional[List[str]] = None,
    default_value: Optional[str] = None
) -> str:
    """
    Validate that a parameter is a valid credential type.
    
    Args:
        params: Dictionary containing parameters
        key: The key to validate
        required: Whether the parameter is required
        valid_types: List of valid credential types
        default_value: Default value to use if the parameter is missing
        
    Returns:
        The validated credential type string
        
    Raises:
        MissingParameterError: If the parameter is required but missing
        InvalidParameterError: If the parameter is not a valid credential type
    """
    if valid_types is None:
        # Default valid credential types
        valid_types = ["VerifiableCredential", "AgentCredential"]
    
    # Check if parameter is missing and we have a default value
    if key not in params and default_value is not None:
        return default_value
    
    # Use the string validator with the allowed choices
    return validate_string(
        params, 
        key, 
        required=required,
        min_length=1,
        choices=valid_types
    ) 