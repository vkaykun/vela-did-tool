"""
Configuration for the vela-did-tool.
This module provides default configuration values and loading from environment
variables or input parameters.
"""

import os
from typing import Dict, Any, List, Optional

# Default credential expiration period in days
DEFAULT_EXPIRATION_DAYS = int(os.environ.get("VELA_CREDENTIAL_EXPIRATION_DAYS", "90"))

# Available credential types 
AVAILABLE_CREDENTIAL_TYPES = [
    "VerifiableCredential",  # Base type (always included)
    "MachineCredential",     # For general machine identity credentials
    "AgentCredential",       # For agent-specific credentials 
    "ComputeCredential",     # For computation results
    "AttestationCredential"  # For attestations about code or systems
]

# Default credential types to use
DEFAULT_CREDENTIAL_TYPES = ["VerifiableCredential", "MachineCredential", "AgentCredential"]

# Security contexts available
SECURITY_CONTEXTS = {
    "base": "https://www.w3.org/2018/credentials/v1",
    "ed25519_2020": "https://w3id.org/security/suites/ed25519-2020/v1"
}

# Default contexts to include in credentials
DEFAULT_CONTEXTS = [SECURITY_CONTEXTS["base"], SECURITY_CONTEXTS["ed25519_2020"]]

class ToolConfig:
    """Configuration manager for vela-did-tool."""
    
    def __init__(self, input_params: Optional[Dict[str, Any]] = None):
        """
        Initialize configuration with optional input parameters.
        
        Args:
            input_params: Optional input parameters dictionary to override defaults
        """
        self.input_params = input_params or {}
        
        # Load values from environment or input parameters
        self.expiration_days = self._get_expiration_days()
        self.credential_types = self._get_credential_types()
        self.contexts = self._get_contexts()
        
    def _get_expiration_days(self) -> int:
        """Get the credential expiration days from input params or environment."""
        # First check input params
        if self.input_params.get("config", {}).get("expiration_days") is not None:
            try:
                days = int(self.input_params["config"]["expiration_days"])
                return max(1, days)  # Ensure at least 1 day
            except (ValueError, TypeError):
                pass
        
        # Fall back to environment variable or default
        return DEFAULT_EXPIRATION_DAYS
    
    def _get_credential_types(self) -> List[str]:
        """Get the credential types to use from input params or defaults."""
        # First check input params
        if self.input_params.get("config", {}).get("credential_types") is not None:
            try:
                types = self.input_params["config"]["credential_types"]
                
                # If it's a string, split by commas
                if isinstance(types, str):
                    types = [t.strip() for t in types.split(",")]
                
                # Ensure it's a list
                if not isinstance(types, list):
                    return DEFAULT_CREDENTIAL_TYPES
                
                # Filter for valid types and always include base VC type
                valid_types = ["VerifiableCredential"]  # Always include the base type
                
                for cred_type in types:
                    if isinstance(cred_type, str) and cred_type in AVAILABLE_CREDENTIAL_TYPES:
                        if cred_type != "VerifiableCredential" and cred_type not in valid_types:
                            valid_types.append(cred_type)
                
                return valid_types
            except Exception:
                pass
        
        # Fall back to defaults
        return DEFAULT_CREDENTIAL_TYPES
    
    def _get_contexts(self) -> List[str]:
        """Get the contexts to include from input params or defaults."""
        # First check input params
        if self.input_params.get("config", {}).get("contexts") is not None:
            try:
                contexts = self.input_params["config"]["contexts"]
                
                # If it's a string, split by commas
                if isinstance(contexts, str):
                    contexts = [c.strip() for c in contexts.split(",")]
                
                # Ensure it's a list
                if not isinstance(contexts, list):
                    return DEFAULT_CONTEXTS
                
                # Always include the base context
                valid_contexts = [SECURITY_CONTEXTS["base"]]
                
                for context in contexts:
                    if isinstance(context, str) and context not in valid_contexts:
                        valid_contexts.append(context)
                
                return valid_contexts
            except Exception:
                pass
        
        # Fall back to defaults
        return DEFAULT_CONTEXTS
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to a dictionary."""
        return {
            "expiration_days": self.expiration_days,
            "credential_types": self.credential_types,
            "contexts": self.contexts
        }
    
    @classmethod
    def from_input(cls, input_params: Dict[str, Any]) -> 'ToolConfig':
        """
        Create a config instance from input parameters.
        
        Args:
            input_params: Input parameters dictionary
            
        Returns:
            A new ToolConfig instance
        """
        return cls(input_params) 