"""
Custom exceptions for the vela-did-tool.
These exceptions provide specific error types with error codes and structured
JSON response formatting.
"""

from typing import Dict, Any, Optional, List


class VelaError(Exception):
    """Base exception class for Vela DID Tool errors."""
    
    # Error code ranges:
    # 1000-1099: Input validation errors
    # 1100-1199: Cryptographic operation errors
    # 1200-1299: DID operation errors
    # 1300-1399: Credential errors
    # 1900-1999: System errors
    
    error_code: int = 1000
    http_status: int = 400  # Default to Bad Request
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        self.message = message
        self.details = details or {}
        super().__init__(self.message)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the exception to a dictionary for JSON response."""
        result = {
            "status": "error",
            "error": {
                "code": self.error_code,
                "message": self.message,
            }
        }
        
        if self.details:
            result["error"]["details"] = self.details
            
        return result


# Input Validation Errors (1000-1099)

class MissingParameterError(VelaError):
    """Raised when a required parameter is missing."""
    error_code = 1001
    
    def __init__(self, parameter: str, message: Optional[str] = None):
        self.parameter = parameter
        super().__init__(
            message or f"Missing required parameter: {parameter}",
            {"parameter": parameter}
        )


class InvalidParameterError(VelaError):
    """Raised when a parameter has an invalid value."""
    error_code = 1002
    
    def __init__(self, parameter: str, reason: str, value: Optional[Any] = None):
        self.parameter = parameter
        self.reason = reason
        details = {"parameter": parameter, "reason": reason}
        if value is not None:
            details["provided_value"] = str(value)
        super().__init__(f"Invalid parameter '{parameter}': {reason}", details)


class SchemaValidationError(VelaError):
    """Raised when input validation fails against a schema."""
    error_code = 1003
    
    def __init__(self, errors: List[str]):
        super().__init__(
            f"Input validation failed: {len(errors)} error(s)",
            {"validation_errors": errors}
        )


# Cryptographic Operation Errors (1100-1199)

class SigningError(VelaError):
    """Raised when a signing operation fails."""
    error_code = 1101
    
    def __init__(self, reason: str, details: Optional[Dict[str, Any]] = None):
        merged_details = {"reason": reason}
        if details:
            merged_details.update(details)
        super().__init__(f"Signing operation failed: {reason}", merged_details)


class VerificationError(VelaError):
    """Raised when a verification operation fails."""
    error_code = 1102
    
    def __init__(self, reason: str, details: Optional[Dict[str, Any]] = None):
        merged_details = {"reason": reason}
        if details:
            merged_details.update(details)
        super().__init__(f"Verification operation failed: {reason}", merged_details)


# DID Operation Errors (1200-1299)

class DIDGenerationError(VelaError):
    """Raised when DID generation fails."""
    error_code = 1201
    
    def __init__(self, reason: str, details: Optional[Dict[str, Any]] = None):
        merged_details = {"reason": reason}
        if details:
            merged_details.update(details)
        super().__init__(f"DID generation failed: {reason}", merged_details)


class DIDResolutionError(VelaError):
    """Raised when DID resolution fails."""
    error_code = 1202
    
    def __init__(self, did: str, reason: str):
        super().__init__(
            f"Failed to resolve DID '{did}': {reason}",
            {"did": did, "reason": reason}
        )


# Credential Errors (1300-1399)

class CredentialError(VelaError):
    """Raised for general credential errors."""
    error_code = 1301
    
    def __init__(self, reason: str, details: Optional[Dict[str, Any]] = None):
        merged_details = {"reason": reason}
        if details:
            merged_details.update(details)
        super().__init__(f"Credential error: {reason}", merged_details)


class CredentialValidationError(CredentialError):
    """Raised when a credential fails structural validation."""
    error_code = 1302
    
    def __init__(self, issues: List[str]):
        super().__init__(
            f"Credential validation failed: {len(issues)} issue(s)",
            {"validation_issues": issues}
        )


class ContentVerificationError(CredentialError):
    """Raised when credential content verification fails."""
    error_code = 1303
    
    def __init__(self, reason: str, expected: Any, actual: Any):
        super().__init__(
            f"Content verification failed: {reason}",
            {
                "reason": reason,
                "expected": expected,
                "actual": actual
            }
        )


# System Errors (1900-1999)

class WAsmIntegrityError(VelaError):
    """Raised when WASM integrity verification fails."""
    error_code = 1901
    http_status = 500  # Internal Server Error
    
    def __init__(self, reason: str, details: Optional[Dict[str, Any]] = None):
        merged_details = {"reason": reason}
        if details:
            merged_details.update(details)
        super().__init__(f"WASM integrity verification failed: {reason}", merged_details)


class ConfigurationError(VelaError):
    """Raised when there's a configuration error."""
    error_code = 1902
    http_status = 500  # Internal Server Error
    
    def __init__(self, reason: str, details: Optional[Dict[str, Any]] = None):
        merged_details = {"reason": reason}
        if details:
            merged_details.update(details)
        super().__init__(f"Configuration error: {reason}", merged_details)


class MockInProductionError(VelaError):
    """Raised when mock implementation is used in production."""
    error_code = 1903
    http_status = 500  # Internal Server Error
    
    def __init__(self):
        super().__init__(
            "CRITICAL SECURITY ERROR: Mock implementation detected in production mode"
        )


class UnknownOperationError(VelaError):
    """Raised when an unknown operation is requested."""
    error_code = 1904
    
    def __init__(self, operation: str, valid_operations: List[str]):
        super().__init__(
            f"Unknown operation: '{operation}'",
            {
                "requested_operation": operation,
                "valid_operations": valid_operations
            }
        ) 