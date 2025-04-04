"""
Production guard for the vela-did-tool.

This module enforces production mode settings and provides guards against
mock implementations being loaded in production environments.
"""

import os
import sys
import importlib.util
import logging
from typing import Optional, Any, NoReturn

# Configure logging
logger = logging.getLogger("vela-did-tool.production_guard")

# Flag to determine if we're in production mode
PRODUCTION_MODE = os.environ.get("VELA_PRODUCTION_MODE", "false").lower() == "true"

# Special build flag for conditional compilation - disables mock code entirely
# This is set during build process via environment variable
# Using VELA_BUILD_TYPE=production will completely exclude mock code
BUILD_TYPE = os.environ.get("VELA_BUILD_TYPE", "development" if not PRODUCTION_MODE else "production")
MOCK_ALLOWED = BUILD_TYPE != "production"

class ProductionMockError(Exception):
    """
    Error raised when attempting to use mock implementations in production.
    This error should never be caught - it should cause the application to crash
    as it indicates a critical security issue.
    """
    pass

def fail_in_production(message: str) -> NoReturn:
    """
    Causes the application to terminate with an error message if in production mode.
    
    Args:
        message: The error message to log
        
    Raises:
        ProductionMockError: Always raised in production mode
        
    Returns:
        NoReturn: This function never returns in production mode
    """
    if PRODUCTION_MODE:
        logger.critical(f"CRITICAL SECURITY ERROR: {message}")
        # Print to stderr as well to ensure visibility
        print(f"CRITICAL SECURITY ERROR: {message}", file=sys.stderr)
        # Exit with error code - this is a non-recoverable error
        raise ProductionMockError(message)
    else:
        # Just log a warning in development mode
        logger.warning(f"MOCK WARNING: {message} (allowed in development mode)")

def verify_no_mocks() -> None:
    """
    Verifies that no mock implementations are present in the codebase.
    This is a safety check that runs at module initialization time in production.
    
    Raises:
        ProductionMockError: If mock files are found in production mode
    """
    if not PRODUCTION_MODE:
        # Skip check in development mode
        return
        
    # Check for the existence of mock files
    mock_files_to_check = [
        # Add all mock implementation files here
        "src/wasm/mock_didkit.py",
        "wasm/mock_didkit.py",
    ]
    
    # Get the base directory - this should be the package root
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    # Check all mock files
    for mock_file in mock_files_to_check:
        file_path = os.path.join(base_dir, mock_file)
        if os.path.exists(file_path):
            fail_in_production(f"Mock implementation file {mock_file} found in production environment")

def guard_import(module_name: str) -> Optional[Any]:
    """
    Guards against importing mock modules in production.
    
    Args:
        module_name: The name of the module to import
        
    Returns:
        The imported module or None if not allowed
        
    Raises:
        ProductionMockError: If attempting to import a mock module in production
    """
    # Check if this is a mock module
    is_mock = "mock" in module_name.lower()
    
    if is_mock and not MOCK_ALLOWED:
        fail_in_production(f"Attempted to import mock module {module_name} in production")
        return None
    
    # In development mode or for non-mock modules, proceed with import
    try:
        return importlib.import_module(module_name)
    except ImportError as e:
        # In production, any import error for a legitimate module is serious
        if PRODUCTION_MODE and not is_mock:
            logger.error(f"Failed to import required module {module_name}: {e}")
            raise
        # In development, we can be more lenient with missing modules
        logger.warning(f"Failed to import module {module_name}: {e}")
        return None

# Run verification at module import time
verify_no_mocks() 