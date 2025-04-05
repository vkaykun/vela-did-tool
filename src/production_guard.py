"""
Production guard to ensure secure operation in production environments.

This module provides utilities to check for production mode and prevent
insecure operations from being used in production environments.
"""

import os
import logging
from typing import Optional, Any

# Configure logging
logger = logging.getLogger("vela-did-tool.production_guard")

# Check if we're in production mode
# This can be set via environment variable or hardcoded for specific deployments
PRODUCTION_MODE = os.environ.get("VELA_PRODUCTION_MODE", "0").lower() in ["1", "true", "yes"]

def fail_in_production(message: str) -> None:
    """
    Fail fast if we're in production mode.
    
    Args:
        message: Error message to log before failing
    
    Raises:
        RuntimeError: If in production mode
    """
    if PRODUCTION_MODE:
        logger.critical(f"SECURITY VIOLATION: {message}")
        logger.critical("Aborting to prevent insecure operation in production")
        raise RuntimeError(f"SECURITY VIOLATION: {message}")
    else:
        logger.warning(f"Development mode: {message}") 