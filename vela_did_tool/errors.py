# vela_did_tool/errors.py
"""Custom exception classes for vela-did-tool."""

class VelaDidToolError(Exception):
    """Base class for tool-specific errors."""
    def __init__(self, message: str, error_code: str = "ToolError"):
        self.message = message
        self.error_code = error_code
        super().__init__(f"[{error_code}] {message}")

class ConfigurationError(VelaDidToolError):
    """Error related to configuration or environment setup."""
    def __init__(self, message: str):
        super().__init__(message, error_code="ConfigurationError")

class InvalidInputError(VelaDidToolError):
    """Error for invalid input data."""
    def __init__(self, message: str):
        super().__init__(message, error_code="InvalidInput")

class DidError(VelaDidToolError):
    """Error related to DID operations."""
    def __init__(self, message: str):
        super().__init__(message, error_code="DidError")

class KeyNotFoundError(VelaDidToolError):
    """Error when a required cryptographic key is not found."""
    def __init__(self, message: str):
        super().__init__(message, error_code="KeyNotFound")

class InvalidKeyFormatError(VelaDidToolError):
    """Error when a key is found but is in an invalid format."""
    def __init__(self, message: str):
        super().__init__(message, error_code="InvalidKeyFormat")

class VcError(VelaDidToolError):
    """Error related to Verifiable Credential operations."""
    def __init__(self, message: str):
        super().__init__(message, error_code="VcError")

class SignatureError(VcError):
    """Error related to cryptographic signature failure."""
    def __init__(self, message: str = "Signature verification failed"):
        super().__init__(message)
        self.error_code = "InvalidSignature"

class NormalizationError(VcError):
    """Error during JSON-LD normalization."""
    def __init__(self, message: str):
        super().__init__(message)
        self.error_code = "NormalizationError"