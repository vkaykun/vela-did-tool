"""Configuration for pytest"""

import pytest
import logging

@pytest.fixture(autouse=True)
def setup_logging():
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(levelname)s - %(name)s - %(message)s'
    )
    
    logging.getLogger('jwcrypto').setLevel(logging.WARNING)
    logging.getLogger('pyld').setLevel(logging.WARNING)
    
    return logging.getLogger() 