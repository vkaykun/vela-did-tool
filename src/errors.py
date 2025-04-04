"""
Custom error types for the Vela DID Tool.

This module defines a hierarchy of error types to provide more structured error reporting.
"""

class VelaError(Exception):
    """Base class for all Vela DID Tool errors."""
    pass


class WasmError(VelaError):
    """Base class for WASM-related errors."""
    pass


class WasmIntegrityError(WasmError):
    """Error raised when WASM binary integrity verification fails."""
    pass


class WasmLoadError(WasmError):
    """Error raised when the WASM module cannot be loaded."""
    pass


class WasmExportError(WasmError):
    """Error raised when a required WASM export is missing."""
    pass


class WasmMemoryError(WasmError):
    """Error raised when there's an issue with WASM memory operations."""
    pass


class DidError(VelaError):
    """Base class for DID-related errors."""
    pass


class DidGenerationError(DidError):
    """Error raised when DID generation fails."""
    pass


class DidResolutionError(DidError):
    """Error raised when DID resolution fails."""
    pass


class CredentialError(VelaError):
    """Base class for credential-related errors."""
    pass


class CredentialCreationError(CredentialError):
    """Error raised when creating a credential fails."""
    pass


class SigningError(CredentialError):
    """Error raised when signing a credential fails."""
    pass


class VerificationError(CredentialError):
    """Error raised when verifying a credential fails."""
    pass


class CredentialFormatError(CredentialError):
    """Error raised when there's an issue with credential format."""
    pass


class CredentialParseError(CredentialError):
    """Error raised when parsing a credential fails."""
    pass


class ProductionGuardError(VelaError):
    """Error raised when a production guard check fails."""
    pass


class SelfTestError(VelaError):
    """Error raised when a self-test fails."""
    pass 