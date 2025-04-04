"""
Low-level wrapper for didkit WASM operations.
This module handles the interface between Python and the compiled didkit WASM.
"""

import os
import json
import logging
import wasmtime
import datetime
import hashlib
from typing import Dict, Any, Optional, Tuple, List

# Import custom error types
from .errors import (
    WasmLoadError,
    WasmIntegrityError,
    WasmExportError,
    WasmMemoryError,
    DidGenerationError,
    DidResolutionError,
    SigningError,
    VerificationError,
    CredentialFormatError
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vela-did-tool.wasm_wrapper")

class DidkitWasm:
    """
    WASM wrapper for DIDKit library using the C-style FFI interface.
    
    This class provides an interface to the DIDKit WASM module, handling memory
    management and C string conversions as required by the DIDKit API.
    """
    
    def __init__(self):
        """Initialize the DIDKit WASM module."""
        wasm_path = os.path.join(os.path.dirname(__file__), "wasm", "didkit_compiled.wasm")
        if not os.path.exists(wasm_path):
            raise WasmLoadError(f"WASM file not found: {wasm_path}")
        
        # Calculate and log WASM file hash for integrity verification
        wasm_hash = self._calculate_wasm_hash(wasm_path)
        logger.info(f"Loading DIDKit WASM from: {wasm_path} (SHA-256: {wasm_hash})")
        
        self.engine = wasmtime.Engine()
        self.store = wasmtime.Store(self.engine)
        self.module = wasmtime.Module.from_file(self.engine, wasm_path)
        self.linker = wasmtime.Linker(self.engine)
        
        # Configure WASI if needed
        # wasi_config = wasmtime.WasiConfig()
        # wasi_config.inherit_stdout()
        # wasi_config.inherit_stderr()
        # self.store.set_wasi(wasi_config)
        
        self.instance = self.linker.instantiate(self.store, self.module)
        
        # Get memory export
        self.memory = self.instance.exports(self.store).get("memory")
        if not isinstance(self.memory, wasmtime.Memory):
            raise WasmLoadError("DIDKit WASM module has no exported 'memory'")
        
        # Get DIDKit version to verify module is loaded
        try:
            version = self._get_version()
            logger.info(f"DIDKit WASM module loaded, version: {version}")
            
            # Verify required exports exist
            self._verify_required_exports()
        except Exception as e:
            logger.error(f"Failed to get DIDKit version: {e}")
            raise WasmLoadError(f"DIDKit WASM module initialization failed: {e}")
    
    def _calculate_wasm_hash(self, wasm_path: str) -> str:
        """
        Calculate SHA-256 hash of the WASM file.
        
        Args:
            wasm_path: Path to the WASM file
            
        Returns:
            SHA-256 hash as a hexadecimal string
        """
        with open(wasm_path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        return file_hash
    
    def _verify_required_exports(self):
        """
        Verify that all required DIDKit exports exist.
        
        Raises:
            WasmExportError: If any required export is missing
        """
        required_exports = [
            "didkit_vc_generate_ed25519_key",
            "didkit_key_to_did",
            "didkit_key_to_verification_method",
            "didkit_vc_issue_credential",
            "didkit_vc_verify_credential",
            "didkit_did_resolve",
            "didkit_free_string",
            "didkit_error_message"
        ]
        
        exports = set()
        for name in dir(self.instance.exports(self.store)):
            if not name.startswith("_"):
                exports.add(name)
        
        missing = [name for name in required_exports if name not in exports]
        if missing:
            raise WasmExportError(f"Missing required DIDKit exports: {', '.join(missing)}")
        
        logger.info(f"Verified required DIDKit exports ({len(required_exports)})")
    
    def _write_string_to_memory(self, text: str) -> int:
        """
        Write a string to WASM memory as a null-terminated UTF-8 string.
        
        Args:
            text: The string to write
            
        Returns:
            The pointer (offset) to the string in WASM memory
        """
        # Convert to UTF-8 bytes with null terminator
        text_bytes = text.encode('utf-8') + b'\x00'
        
        # Get current memory size and data
        mem_view = self.memory.data_ptr(self.store)
        mem_size = self.memory.data_size(self.store)
        
        # Check if we need to grow memory
        if mem_size - 1024 < len(text_bytes):  # Leave 1KB buffer
            pages_needed = (len(text_bytes) + 65535) // 65536  # Round up to pages (64KB)
            self.memory.grow(self.store, pages_needed)
            mem_view = self.memory.data_ptr(self.store)
            mem_size = self.memory.data_size(self.store)
            logger.debug(f"Grew WASM memory to {mem_size} bytes")
            
        # Find a position to write - simple approach: use high memory
        # In real apps, we'd implement a proper allocator
        # For this demo, we'll use a simple approach with a high offset 
        offset = mem_size - 1024 - len(text_bytes)
        
        # Copy bytes to memory
        for i, b in enumerate(text_bytes):
            mem_view[offset + i] = b
            
        return offset
    
    def _read_string_from_memory(self, ptr: int) -> str:
        """
        Read a null-terminated UTF-8 string from WASM memory.
        
        Args:
            ptr: The pointer (offset) to the string in memory
            
        Returns:
            The decoded string
        """
        if ptr == 0:
            return ""
            
        mem_view = self.memory.data_ptr(self.store)
        mem_size = self.memory.data_size(self.store)
        
        if ptr >= mem_size:
            raise WasmMemoryError(f"Memory pointer ({ptr}) out of bounds (size: {mem_size})")
        
        # Read until null terminator
        end = ptr
        while end < mem_size and mem_view[end] != 0:
            end += 1
        
        if end >= mem_size:
            raise WasmMemoryError("No null terminator found in memory")
        
        # Convert bytes to string
        byte_data = bytes(mem_view[ptr:end])
        return byte_data.decode('utf-8')
    
    def _free_string(self, ptr: int) -> None:
        """
        Free a string allocated by DIDKit.
        
        Args:
            ptr: Pointer to the string to free
        """
        if ptr == 0:
            return
            
        try:
            free_func = self.instance.exports(self.store).get("didkit_free_string")
            if free_func and isinstance(free_func, wasmtime.Func):
                free_func(self.store, ptr)
            else:
                logger.warning("didkit_free_string function not found")
        except Exception as e:
            logger.error(f"Error freeing string: {e}")
    
    def _get_error_message(self) -> str:
        """
        Get the last error message from DIDKit.
        
        Returns:
            The error message
        """
        try:
            error_func = self.instance.exports(self.store).get("didkit_error_message")
            if error_func and isinstance(error_func, wasmtime.Func):
                ptr = error_func(self.store)
                if ptr:
                    error_msg = self._read_string_from_memory(ptr)
                    # Note: Don't free the error message - it's managed by DIDKit
                    return error_msg
            return "Unknown error (didkit_error_message not found)"
        except Exception as e:
            return f"Error retrieving error message: {e}"
    
    def _get_version(self) -> str:
        """
        Get the DIDKit version.
        
        Returns:
            The DIDKit version string
        """
        version_func = self.instance.exports(self.store).get("didkit_get_version")
        if not version_func or not isinstance(version_func, wasmtime.Func):
            raise WasmExportError("didkit_get_version function not found")
        
        ptr = 0
        try:
            ptr = version_func(self.store)
            if ptr == 0:
                raise WasmLoadError("Failed to get DIDKit version")
                
            version = self._read_string_from_memory(ptr)
            return version
        finally:
            if ptr != 0:
                self._free_string(ptr)
    
    def generate_ed25519_key(self) -> Dict[str, Any]:
        """
        Generate a new Ed25519 key pair.
        
        Returns:
            The generated key as a JWK dict
        
        Raises:
            DidGenerationError: If key generation fails
        """
        gen_func = self.instance.exports(self.store).get("didkit_vc_generate_ed25519_key")
        if not gen_func or not isinstance(gen_func, wasmtime.Func):
            raise WasmExportError("didkit_vc_generate_ed25519_key function not found")
        
        ptr = 0
        try:    
            ptr = gen_func(self.store)
            if ptr == 0:
                error = self._get_error_message()
                raise DidGenerationError(f"Failed to generate Ed25519 key: {error}")
                
            key_str = self._read_string_from_memory(ptr)
            
            try:
                return json.loads(key_str)
            except json.JSONDecodeError as e:
                raise CredentialFormatError(f"Invalid key JWK JSON returned: {e}")
        finally:
            if ptr != 0:
                self._free_string(ptr)
    
    def key_to_did(self, method: str, jwk: Dict[str, Any]) -> str:
        """
        Convert a JWK to a DID string.
        
        Args:
            method: DID method (e.g. "key", "web", "ethr")
            jwk: JWK of the key as a dict
            
        Returns:
            The generated DID string
        
        Raises:
            DidGenerationError: If converting key to DID fails
        """
        jwk_str = json.dumps(jwk)
        
        method_ptr = self._write_string_to_memory(method)
        jwk_ptr = self._write_string_to_memory(jwk_str)
        
        did_func = self.instance.exports(self.store).get("didkit_key_to_did")
        if not did_func or not isinstance(did_func, wasmtime.Func):
            raise WasmExportError("didkit_key_to_did function not found")
        
        result_ptr = 0
        try:
            result_ptr = did_func(self.store, method_ptr, jwk_ptr)
            if result_ptr == 0:
                error = self._get_error_message()
                raise DidGenerationError(f"Failed to convert key to DID: {error}")
                
            did = self._read_string_from_memory(result_ptr)
            return did
        finally:
            if result_ptr != 0:
                self._free_string(result_ptr)
    
    def key_to_verification_method(self, method: str, jwk: Dict[str, Any]) -> str:
        """
        Convert a JWK to a verification method string.
        
        Args:
            method: DID method (e.g. "key", "web", "ethr")
            jwk: JWK of the key as a dict
            
        Returns:
            The generated verification method string
        
        Raises:
            DidGenerationError: If converting key to verification method fails
        """
        jwk_str = json.dumps(jwk)
        
        method_ptr = self._write_string_to_memory(method)
        jwk_ptr = self._write_string_to_memory(jwk_str)
        
        vm_func = self.instance.exports(self.store).get("didkit_key_to_verification_method")
        if not vm_func or not isinstance(vm_func, wasmtime.Func):
            raise WasmExportError("didkit_key_to_verification_method function not found")
        
        result_ptr = 0
        try:
            result_ptr = vm_func(self.store, method_ptr, jwk_ptr)
            if result_ptr == 0:
                error = self._get_error_message()
                raise DidGenerationError(f"Failed to convert key to verification method: {error}")
                
            vm = self._read_string_from_memory(result_ptr)
            return vm
        finally:
            if result_ptr != 0:
                self._free_string(result_ptr)
    
    def issue_credential(self, credential: Dict[str, Any], options: Dict[str, Any], 
                         key: Dict[str, Any]) -> Dict[str, Any]:
        """
        Issue a Verifiable Credential.
        
        Args:
            credential: The unsigned credential as a dict
            options: Credential issuance options as a dict
            key: The issuer's private key as a JWK dict
            
        Returns:
            The issued (signed) credential as a dict
        
        Raises:
            SigningError: If credential issuance fails
            CredentialFormatError: If JSON parsing/formatting fails
        """
        # Input validation to avoid crashes
        if not isinstance(credential, dict):
            raise TypeError("credential must be a dictionary")
        if not isinstance(options, dict):
            raise TypeError("options must be a dictionary")
        if not isinstance(key, dict) or 'd' not in key:
            raise TypeError("key must be a JWK dictionary with private key ('d' property)")
            
        # Ensure options contains required fields
        if 'proofPurpose' not in options:
            logger.warning("No proofPurpose specified in options, defaulting to 'assertionMethod'")
            options['proofPurpose'] = 'assertionMethod'
        
        # Convert dict inputs to JSON strings
        cred_str = json.dumps(credential)
        opt_str = json.dumps(options)
        key_str = json.dumps(key)
        
        # Pointers to track for cleanup
        input_ptrs = []
        result_ptr = 0
        
        try:
            # Write inputs to WASM memory
            cred_ptr = self._write_string_to_memory(cred_str)
            input_ptrs.append(cred_ptr)
            
            opt_ptr = self._write_string_to_memory(opt_str)
            input_ptrs.append(opt_ptr)
            
            key_ptr = self._write_string_to_memory(key_str)
            input_ptrs.append(key_ptr)
            
            # Get the issuance function
            issue_func = self.instance.exports(self.store).get("didkit_vc_issue_credential")
            if not issue_func or not isinstance(issue_func, wasmtime.Func):
                raise WasmExportError("didkit_vc_issue_credential function not found")
            
            # Call the function
            result_ptr = issue_func(self.store, cred_ptr, opt_ptr, key_ptr)
            if result_ptr == 0:
                error = self._get_error_message()
                raise SigningError(f"Failed to issue credential: {error}")
                
            # Read the result
            signed_cred_str = self._read_string_from_memory(result_ptr)
            
            # Parse the JSON result
            try:
                return json.loads(signed_cred_str)
            except json.JSONDecodeError as e:
                raise CredentialFormatError(f"Invalid signed credential JSON returned: {e}")
        finally:
            # Always free allocated memory, even if exceptions occur
            if result_ptr != 0:
                self._free_string(result_ptr)
            
            # We don't need to free input pointers as they're allocated in our application memory
            # space, not by DIDKit
    
    def verify_credential(self, credential: Dict[str, Any], options: Dict[str, Any]) -> Dict[str, Any]:
        """
        Verify a Verifiable Credential.
        
        Args:
            credential: The credential to verify as a dict
            options: Verification options as a dict
            
        Returns:
            The verification result as a dict
        
        Raises:
            VerificationError: If credential verification fails
            CredentialFormatError: If JSON parsing/formatting fails
        """
        # Input validation
        if not isinstance(credential, dict):
            raise TypeError("credential must be a dictionary")
        if not isinstance(options, dict):
            raise TypeError("options must be a dictionary")
            
        # Ensure options contains recommended security fields 
        if 'proofPurpose' not in options:
            logger.warning("No proofPurpose specified in options, defaulting to 'assertionMethod'")
            options['proofPurpose'] = 'assertionMethod'
        
        # Convert dict inputs to JSON strings
        cred_str = json.dumps(credential)
        opt_str = json.dumps(options)
        
        # Pointers to track for cleanup
        result_ptr = 0
        
        try:
            # Write inputs to WASM memory
            cred_ptr = self._write_string_to_memory(cred_str)
            opt_ptr = self._write_string_to_memory(opt_str)
            
            # Get the verification function
            verify_func = self.instance.exports(self.store).get("didkit_vc_verify_credential")
            if not verify_func or not isinstance(verify_func, wasmtime.Func):
                raise WasmExportError("didkit_vc_verify_credential function not found")
            
            # Call the function
            result_ptr = verify_func(self.store, cred_ptr, opt_ptr)
            if result_ptr == 0:
                error = self._get_error_message()
                raise VerificationError(f"Failed to verify credential: {error}")
                
            # Read the result
            result_str = self._read_string_from_memory(result_ptr)
            
            # Parse the JSON result
            try:
                return json.loads(result_str)
            except json.JSONDecodeError as e:
                raise CredentialFormatError(f"Invalid verification result JSON returned: {e}")
        finally:
            # Always free allocated memory, even if exceptions occur
            if result_ptr != 0:
                self._free_string(result_ptr)
    
    def resolve_did(self, did: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Resolve a DID to a DID document.
        
        Args:
            did: The DID to resolve
            options: Resolution options (optional)
            
        Returns:
            The DID document as a dict
        
        Raises:
            DidResolutionError: If DID resolution fails
            CredentialFormatError: If JSON parsing/formatting fails
        """
        # Input validation
        if not did or not isinstance(did, str):
            raise TypeError("did must be a non-empty string")
            
        if options is None:
            options = {}
        elif not isinstance(options, dict):
            raise TypeError("options must be a dictionary")
            
        # Convert inputs to strings
        options_str = json.dumps(options)
        
        # Pointers to track for cleanup
        result_ptr = 0
        
        try:
            # Write inputs to WASM memory
            did_ptr = self._write_string_to_memory(did)
            opt_ptr = self._write_string_to_memory(options_str)
            
            # Get the resolution function
            resolve_func = self.instance.exports(self.store).get("didkit_did_resolve")
            if not resolve_func or not isinstance(resolve_func, wasmtime.Func):
                raise WasmExportError("didkit_did_resolve function not found")
            
            # Call the function
            result_ptr = resolve_func(self.store, did_ptr, opt_ptr)
            if result_ptr == 0:
                error = self._get_error_message()
                raise DidResolutionError(f"Failed to resolve DID: {error}")
                
            # Read the result
            result_str = self._read_string_from_memory(result_ptr)
            
            # Parse the JSON result
            try:
                return json.loads(result_str)
            except json.JSONDecodeError as e:
                raise CredentialFormatError(f"Invalid DID document JSON returned: {e}")
        finally:
            # Always free allocated memory, even if exceptions occur
            if result_ptr != 0:
                self._free_string(result_ptr) 