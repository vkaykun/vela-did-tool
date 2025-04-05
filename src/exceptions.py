"""
Custom exceptions for the Vela DID Tool.

This module defines custom exceptions used throughout the tool.
"""

from typing import Dict, Any, Optional
import sys


class VelaError(Exception):
    """Base class for all Vela DID Tool errors."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        """
        Initialize a new VelaError.
        
        Args:
            message: Error message
            details: Optional dictionary with additional error details
        """
        self.message = message
        self.details = details or {}
        super().__init__(message)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the error to a dictionary representation.
        
        Returns:
            Dictionary with error details
        """
        result = {
            "type": self.__class__.__name__,
            "message": self.message
        }
        
        if self.details:
            result["details"] = self.details
            
        return result


class ConfigError(VelaError):
    """Raised when there's an error with the configuration."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        """
        Initialize a new ConfigError.
        
        Args:
            message: Error message
            details: Optional dictionary with additional error details
        """
        merged_details = {"error_type": "configuration"}
        if details:
            merged_details.update(details)
        super().__init__(f"Configuration error: {message}", merged_details)


class ParameterError(VelaError):
    """Raised when a parameter is missing or invalid."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        """
        Initialize a new ParameterError.
        
        Args:
            message: Error message
            details: Optional dictionary with additional error details
        """
        merged_details = {"error_type": "parameter_validation"}
        if details:
            merged_details.update(details)
        super().__init__(f"Parameter error: {message}", merged_details)


class InputError(VelaError):
    """Base class for input-related errors."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        """
        Initialize a new InputError.
        
        Args:
            message: Error message
            details: Optional dictionary with additional error details
        """
        merged_details = {"error_type": "input"}
        if details:
            merged_details.update(details)
        super().__init__(message, merged_details)


class MissingParameterError(InputError):
    """Error raised when a required parameter is missing."""
    
    def __init__(self, parameter_name: str, details: Optional[Dict[str, Any]] = None):
        """
        Initialize a new MissingParameterError.
        
        Args:
            parameter_name: Name of the missing parameter
            details: Optional dictionary with additional error details
        """
        merged_details = {"parameter_name": parameter_name}
        if details:
            merged_details.update(details)
        super().__init__(f"Missing required parameter '{parameter_name}'", merged_details)


class InvalidParameterError(InputError):
    """Error raised when a parameter has an invalid value."""
    
    def __init__(self, parameter_name: str, reason: Optional[str] = None, 
                 details: Optional[Dict[str, Any]] = None):
        """
        Initialize a new InvalidParameterError.
        
        Args:
            parameter_name: Name of the invalid parameter
            reason: Optional reason for why the parameter is invalid
            details: Optional dictionary with additional error details
        """
        message = f"Invalid parameter '{parameter_name}'"
        if reason:
            message += f": {reason}"
            
        merged_details = {"parameter_name": parameter_name}
        if reason:
            merged_details["reason"] = reason
        if details:
            merged_details.update(details)
            
        super().__init__(message, merged_details)


class SchemaValidationError(InputError):
    """Error raised when JSON schema validation fails."""
    
    def __init__(self, errors: Any, details: Optional[Dict[str, Any]] = None):
        """
        Initialize a new SchemaValidationError.
        
        Args:
            errors: Validation errors
            details: Optional dictionary with additional error details
        """
        message = f"Schema validation failed: {errors}"
        merged_details = {"validation_errors": errors}
        if details:
            merged_details.update(details)
        super().__init__(message, merged_details)


class CredentialError(VelaError):
    """Raised when there's an error with a credential."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        """
        Initialize a new CredentialError.
        
        Args:
            message: Error message
            details: Optional dictionary with additional error details
        """
        merged_details = {"error_type": "credential"}
        if details:
            merged_details.update(details)
        super().__init__(f"Credential error: {message}", merged_details)


class CredentialCreationError(CredentialError):
    """Error raised when creating a credential fails."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        """
        Initialize a new CredentialCreationError.
        
        Args:
            message: Error message
            details: Optional dictionary with additional error details
        """
        merged_details = {"error_subtype": "creation"}
        if details:
            merged_details.update(details)
        super().__init__(message, merged_details)


class CredentialFormatError(CredentialError):
    """Error raised when there's an issue with credential format."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        """
        Initialize a new CredentialFormatError.
        
        Args:
            message: Error message
            details: Optional dictionary with additional error details
        """
        merged_details = {"error_subtype": "format"}
        if details:
            merged_details.update(details)
        super().__init__(message, merged_details)


class CredentialParseError(CredentialError):
    """Error raised when parsing a credential fails."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        """
        Initialize a new CredentialParseError.
        
        Args:
            message: Error message
            details: Optional dictionary with additional error details
        """
        merged_details = {"error_subtype": "parse"}
        if details:
            merged_details.update(details)
        super().__init__(message, merged_details)


class SigningError(VelaError):
    """Raised when there's an error signing a message."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        """
        Initialize a new SigningError.
        
        Args:
            message: Error message
            details: Optional dictionary with additional error details
        """
        merged_details = {"error_type": "signing"}
        if details:
            merged_details.update(details)
        super().__init__(f"Signing error: {message}", merged_details)


class VerificationError(VelaError):
    """Raised when there's an error verifying a signature."""
    
    def __init__(self, message: str, context: Optional[Dict[str, Any]] = None, 
                 code: int = 1200, details: Optional[Dict[str, Any]] = None):
        """
        Initialize a new VerificationError.
        
        Args:
            message: Error message
            context: Context information about the verification
            code: Error code
            details: Optional dictionary with additional error details
        """
        merged_details = {
            "error_type": "verification",
            "code": code
        }
        if context:
            merged_details["context"] = context
        if details:
            merged_details.update(details)
        super().__init__(f"Verification error: {message}", merged_details)


class PresentationError(VelaError):
    """Base class for presentation-related errors."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        """
        Initialize a new PresentationError.
        
        Args:
            message: Error message
            details: Optional dictionary with additional error details
        """
        merged_details = {"error_type": "presentation"}
        if details:
            merged_details.update(details)
        super().__init__(f"Presentation error: {message}", merged_details)


class PresentationFormatError(PresentationError):
    """Error raised when there's an issue with presentation format."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        """
        Initialize a new PresentationFormatError.
        
        Args:
            message: Error message
            details: Optional dictionary with additional error details
        """
        merged_details = {"error_subtype": "format"}
        if details:
            merged_details.update(details)
        super().__init__(message, merged_details)


class OperationError(VelaError):
    """Raised when there's an error with an operation."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        """
        Initialize a new OperationError.
        
        Args:
            message: Error message
            details: Optional dictionary with additional error details
        """
        merged_details = {"error_type": "operation"}
        if details:
            merged_details.update(details)
        super().__init__(f"Operation error: {message}", merged_details)


class UnsupportedOperationError(OperationError):
    """Raised when an unsupported operation is requested."""
    
    def __init__(self, operation: str, details: Optional[Dict[str, Any]] = None):
        """
        Initialize a new UnsupportedOperationError.
        
        Args:
            operation: The unsupported operation name
            details: Optional dictionary with additional error details
        """
        merged_details = {"unsupported_operation": operation}
        if details:
            merged_details.update(details)
        super().__init__(f"Unsupported operation: {operation}", merged_details)


class SecurityError(VelaError):
    """Raised when there's a security-related error."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        """
        Initialize a new SecurityError.
        
        Args:
            message: Error message
            details: Optional dictionary with additional error details
        """
        merged_details = {"error_type": "security"}
        if details:
            merged_details.update(details)
        super().__init__(f"Security error: {message}", merged_details)


class ProductionModeError(SecurityError):
    """Raised when a non-production feature is used in production mode."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        """
        Initialize a new ProductionModeError.
        
        Args:
            message: Error message
            details: Optional dictionary with additional error details
        """
        merged_details = {"error_subtype": "production_mode"}
        if details:
            merged_details.update(details)
        super().__init__(f"Production mode violation: {message}", merged_details)


class ProductionGuardError(SecurityError):
    """Error raised when a production guard check fails."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        """
        Initialize a new ProductionGuardError.
        
        Args:
            message: Error message
            details: Optional dictionary with additional error details
        """
        merged_details = {"error_subtype": "production_guard"}
        if details:
            merged_details.update(details)
        super().__init__(f"Production guard error: {message}", merged_details)


class SelfTestError(VelaError):
    """Error raised when a self-test fails."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        """
        Initialize a new SelfTestError.
        
        Args:
            message: Error message
            details: Optional dictionary with additional error details
        """
        merged_details = {"error_type": "self_test"}
        if details:
            merged_details.update(details)
        super().__init__(f"Self-test failure: {message}", merged_details)


class DidError(VelaError):
    """Base class for DID-related errors."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        """
        Initialize a new DidError.
        
        Args:
            message: Error message
            details: Optional dictionary with additional error details
        """
        merged_details = {"error_type": "did"}
        if details:
            merged_details.update(details)
        super().__init__(f"DID error: {message}", merged_details)


class DidGenerationError(DidError):
    """Error raised when DID generation fails."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        """
        Initialize a new DidGenerationError.
        
        Args:
            message: Error message
            details: Optional dictionary with additional error details
        """
        merged_details = {"error_subtype": "generation"}
        if details:
            merged_details.update(details)
        super().__init__(message, merged_details)


class DidResolutionError(DidError):
    """Error raised when DID resolution fails."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        """
        Initialize a new DidResolutionError.
        
        Args:
            message: Error message
            details: Optional dictionary with additional error details
        """
        merged_details = {"error_subtype": "resolution"}
        if details:
            merged_details.update(details)
        super().__init__(message, merged_details)


class SecretError(VelaError):
    """Base class for secret-related errors."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        """
        Initialize a new SecretError.
        
        Args:
            message: Error message
            details: Optional dictionary with additional error details
        """
        merged_details = {"error_type": "secret"}
        if details:
            merged_details.update(details)
        super().__init__(f"Secret error: {message}", merged_details)


class SecretRetrievalError(SecretError):
    """Error raised when retrieving a secret fails."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        """
        Initialize a new SecretRetrievalError.
        
        Args:
            message: Error message
            details: Optional dictionary with additional error details
        """
        merged_details = {"error_subtype": "retrieval"}
        if details:
            merged_details.update(details)
        super().__init__(message, merged_details)


class SecretStorageError(SecretError):
    """Error raised when storing a secret fails."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        """
        Initialize a new SecretStorageError.
        
        Args:
            message: Error message
            details: Optional dictionary with additional error details
        """
        merged_details = {"error_subtype": "storage"}
        if details:
            merged_details.update(details)
        super().__init__(message, merged_details)


# Add an alias for backward compatibility
errors = sys.modules[__name__] 