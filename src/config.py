"""
Configuration for the Vela DID Tool.

This module provides configuration classes and constants for the tool.
"""

from typing import Dict, Any, List, Optional
import os
import logging

# Configure logging
logger = logging.getLogger(__name__)

# Default values
DEFAULT_CREDENTIAL_TYPE = "VerifiableCredential"
DEFAULT_CONTEXT = "https://www.w3.org/2018/credentials/v1"
DEFAULT_EXPIRATION_DAYS = 365  # 1 year
DEFAULT_TEST_MESSAGE = "vela-did-tool self-test passed"

# Available credential types
AVAILABLE_CREDENTIAL_TYPES = [
    "VerifiableCredential",
    "AgentCredential",
    "MachineCredential"
]

class ToolConfig:
    """
    Configuration for the Vela DID Tool.
    This class handles the configuration of the tool, loading values
    from environment variables or input parameters.
    """
    
    def __init__(self):
        """Initialize a new configuration instance with default values."""
        # Initialize with defaults
        self.debug_mode = False
        self.credential_type = DEFAULT_CREDENTIAL_TYPE
        self.credential_context = DEFAULT_CONTEXT
        self.expiration_days = DEFAULT_EXPIRATION_DAYS
    
    @classmethod
    def from_input(cls, params: Optional[Dict[str, Any]] = None) -> 'ToolConfig':
        """
        Create a configuration from input parameters.
        
        Args:
            params: Input parameters dictionary
            
        Returns:
            A configured ToolConfig instance
        """
        config = cls()
        
        # Skip if no params provided
        if not params:
            return config
        
        # Debug mode overriding
        if "debug" in params:
            config.debug_mode = params["debug"] is True or (
                isinstance(params["debug"], str) and
                params["debug"].lower() in ("true", "yes", "1")
            )
        
        # Set logging level based on debug mode
        if config.debug_mode:
            logging.getLogger().setLevel(logging.DEBUG)
            logger.debug("Debug mode enabled")
        
        # Credential configuration
        if "credential_type" in params:
            config.credential_type = params["credential_type"]
            logger.debug(f"Using credential type: {config.credential_type}")
        
        if "credential_context" in params:
            config.credential_context = params["credential_context"]
            logger.debug(f"Using credential context: {config.credential_context}")
        
        if "expiration_days" in params:
            try:
                config.expiration_days = int(params["expiration_days"])
                logger.debug(f"Using expiration days: {config.expiration_days}")
            except (ValueError, TypeError):
                logger.warning(f"Invalid expiration_days value: {params['expiration_days']}")
        
        return config
    
    def get_credential_types(self) -> List[str]:
        """
        Get the list of credential types to use.
        
        Returns:
            List of credential types
        """
        # If credential_type is a list, return it directly
        if isinstance(self.credential_type, list):
            return self.credential_type
        
        # Otherwise, wrap it in a list with the default credential type first
        return [DEFAULT_CREDENTIAL_TYPE, self.credential_type] if self.credential_type != DEFAULT_CREDENTIAL_TYPE else [DEFAULT_CREDENTIAL_TYPE]
    
    def get_contexts(self) -> List[str]:
        """
        Get the list of contexts to use.
        
        Returns:
            List of contexts
        """
        # If credential_context is a list, return it directly
        if isinstance(self.credential_context, list):
            return self.credential_context
        
        # Otherwise, wrap it in a list with the default context first
        return [DEFAULT_CONTEXT]
    
    def get_expiration_days(self) -> int:
        """
        Get the number of days until the credential expires.
        
        Returns:
            Number of days
        """
        return self.expiration_days
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the configuration to a dictionary.
        
        Returns:
            Dictionary representation of the configuration
        """
        return {
            "debug_mode": self.debug_mode,
            "credential_type": self.credential_type,
            "credential_context": self.credential_context,
            "expiration_days": self.expiration_days,
            "credential_types": self.get_credential_types(),
            "contexts": self.get_contexts()
        } 