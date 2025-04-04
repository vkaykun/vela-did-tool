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
    SchemaValidationError
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
    parameter: str, 
    required: bool = True,
    min_length: Optional[int] = None,
    max_length: Optional[int] = None,
    pattern: Optional[str] = None,
    default: Optional[str] = None
) -> Optional[str]:
    """
    Validates a string parameter.
    
    Args:
        params: The parameters dictionary
        parameter: The name of the parameter to validate
        required: Whether the parameter is required
        min_length: Minimum length of the string
        max_length: Maximum length of the string
        pattern: Regex pattern the string must match
        default: Default value if parameter is missing
        
    Returns:
        The validated string or default
        
    Raises:
        MissingParameterError: If a required parameter is missing
        InvalidParameterError: If validation fails
    """
    # Get value based on required flag
    if required:
        value = validate_required(params, parameter)
    else:
        value = validate_optional(params, parameter, default)
        if value is None:
            return None
    
    # Ensure value is a string
    if not isinstance(value, str):
        raise InvalidParameterError(
            parameter,
            f"Must be a string, got {type(value).__name__}",
            value
        )
    
    # Strip value
    value = value.strip()
    
    # Check minimum length
    if min_length is not None and len(value) < min_length:
        raise InvalidParameterError(
            parameter,
            f"Must be at least {min_length} characters long",
            value
        )
    
    # Check maximum length
    if max_length is not None and len(value) > max_length:
        raise InvalidParameterError(
            parameter,
            f"Must be at most {max_length} characters long",
            value
        )
    
    # Check pattern
    if pattern is not None and not re.match(pattern, value):
        raise InvalidParameterError(
            parameter,
            f"Does not match required pattern: {pattern}",
            value
        )
    
    return value


def validate_integer(
    params: Dict[str, Any], 
    parameter: str, 
    required: bool = True,
    min_value: Optional[int] = None,
    max_value: Optional[int] = None,
    default: Optional[int] = None
) -> Optional[int]:
    """
    Validates an integer parameter.
    
    Args:
        params: The parameters dictionary
        parameter: The name of the parameter to validate
        required: Whether the parameter is required
        min_value: Minimum value allowed
        max_value: Maximum value allowed
        default: Default value if parameter is missing
        
    Returns:
        The validated integer or default
        
    Raises:
        MissingParameterError: If a required parameter is missing
        InvalidParameterError: If validation fails
    """
    # Get value based on required flag
    if required:
        value = validate_required(params, parameter)
    else:
        value = validate_optional(params, parameter, default)
        if value is None:
            return default
    
    # Convert to integer if string
    if isinstance(value, str):
        try:
            value = int(value.strip())
        except ValueError:
            raise InvalidParameterError(
                parameter,
                "Must be a valid integer",
                value
            )
    
    # Ensure value is an integer
    if not isinstance(value, int):
        raise InvalidParameterError(
            parameter,
            f"Must be an integer, got {type(value).__name__}",
            value
        )
    
    # Check minimum value
    if min_value is not None and value < min_value:
        raise InvalidParameterError(
            parameter,
            f"Must be at least {min_value}",
            value
        )
    
    # Check maximum value
    if max_value is not None and value > max_value:
        raise InvalidParameterError(
            parameter,
            f"Must be at most {max_value}",
            value
        )
    
    return value


def validate_did(
    params: Dict[str, Any], 
    parameter: str, 
    required: bool = True,
    default: Optional[str] = None
) -> Optional[str]:
    """
    Validates a DID parameter.
    
    Args:
        params: The parameters dictionary
        parameter: The name of the parameter to validate
        required: Whether the parameter is required
        default: Default value if parameter is missing
        
    Returns:
        The validated DID or default
        
    Raises:
        MissingParameterError: If a required parameter is missing
        InvalidParameterError: If validation fails
    """
    did_pattern = r'^did:[a-z0-9]+:.+$'
    
    value = validate_string(
        params, 
        parameter, 
        required=required, 
        pattern=did_pattern, 
        default=default
    )
    
    return value


def validate_jwk(
    params: Dict[str, Any], 
    parameter: str, 
    required: bool = True
) -> Optional[Dict[str, Any]]:
    """
    Validates a JWK parameter.
    
    Args:
        params: The parameters dictionary
        parameter: The name of the parameter to validate
        required: Whether the parameter is required
        
    Returns:
        The validated JWK as dict
        
    Raises:
        MissingParameterError: If a required parameter is missing
        InvalidParameterError: If validation fails
    """
    # Get value
    if required:
        value = validate_required(params, parameter)
    else:
        value = validate_optional(params, parameter)
        if value is None:
            return None
    
    # If string, try to parse as JSON
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            raise InvalidParameterError(
                parameter,
                "Must be a valid JSON object",
                value
            )
    
    # Ensure value is a dict
    if not isinstance(value, dict):
        raise InvalidParameterError(
            parameter,
            f"Must be a JWK object, got {type(value).__name__}",
            value
        )
    
    # Validate JWK structure
    required_jwk_fields = ['kty']
    missing_fields = [field for field in required_jwk_fields if field not in value]
    
    if missing_fields:
        raise InvalidParameterError(
            parameter,
            f"Invalid JWK: missing required fields: {', '.join(missing_fields)}",
            value
        )
    
    # Check for private key component
    if required and 'd' not in value:
        raise InvalidParameterError(
            parameter,
            "Private key component ('d') is required for signing operations",
            value
        )
    
    return value


def validate_credential(
    params: Dict[str, Any], 
    parameter: str, 
    required: bool = True
) -> Optional[Union[Dict[str, Any], str]]:
    """
    Validates a verifiable credential parameter.
    
    Args:
        params: The parameters dictionary
        parameter: The name of the parameter to validate
        required: Whether the parameter is required
        
    Returns:
        The validated credential (as string or dict)
        
    Raises:
        MissingParameterError: If a required parameter is missing
        InvalidParameterError: If validation fails
    """
    # Get value
    if required:
        value = validate_required(params, parameter)
    else:
        value = validate_optional(params, parameter)
        if value is None:
            return None
    
    # If it's a string that looks like JSON, try to parse it
    if isinstance(value, str) and value.strip().startswith('{'):
        try:
            # Just validate it's parseable, but return the original string
            json.loads(value)
        except json.JSONDecodeError:
            raise InvalidParameterError(
                parameter,
                "Invalid JSON format",
                value
            )
    # If it's a dict, just return it
    elif isinstance(value, dict):
        pass
    # If it's a string that doesn't look like JSON, it might be a JWT
    elif isinstance(value, str):
        # Basic JWT format check (three base64-encoded parts separated by dots)
        if not re.match(r'^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$', value):
            raise InvalidParameterError(
                parameter,
                "Invalid credential format: must be valid JSON or JWT",
                value
            )
    else:
        raise InvalidParameterError(
            parameter,
            f"Must be a verifiable credential as JSON or JWT, got {type(value).__name__}",
            value
        )
    
    return value


def validate_verification_method(
    params: Dict[str, Any], 
    parameter: str, 
    required: bool = True,
    default: Optional[str] = None
) -> Optional[str]:
    """
    Validates a verification method parameter.
    
    Args:
        params: The parameters dictionary
        parameter: The name of the parameter to validate
        required: Whether the parameter is required
        default: Default value if parameter is missing
        
    Returns:
        The validated verification method or default
        
    Raises:
        MissingParameterError: If a required parameter is missing
        InvalidParameterError: If validation fails
    """
    # Verification method should be a DID URL (DID with fragment)
    vm_pattern = r'^did:[a-z0-9]+:.+#.+$'
    
    value = validate_string(
        params, 
        parameter, 
        required=required, 
        pattern=vm_pattern if required else None,  # Only enforce pattern if required
        default=default
    )
    
    return value


def validate_credential_type(
    params: Dict[str, Any], 
    parameter: str, 
    allowed_types: List[str],
    required: bool = False,
    default: Optional[str] = None
) -> Optional[str]:
    """
    Validates a credential type parameter.
    
    Args:
        params: The parameters dictionary
        parameter: The name of the parameter to validate
        allowed_types: List of allowed credential types
        required: Whether the parameter is required
        default: Default value if parameter is missing
        
    Returns:
        The validated credential type or default
        
    Raises:
        MissingParameterError: If a required parameter is missing
        InvalidParameterError: If validation fails
    """
    # Get value
    if required:
        value = validate_required(params, parameter)
    else:
        value = validate_optional(params, parameter, default)
        if value is None:
            return default
    
    # Ensure value is a string
    if not isinstance(value, str):
        raise InvalidParameterError(
            parameter,
            f"Must be a string, got {type(value).__name__}",
            value
        )
    
    # Validate against allowed types
    if value not in allowed_types:
        raise InvalidParameterError(
            parameter,
            f"Must be one of: {', '.join(allowed_types)}",
            value
        )
    
    return value 