"""
Configuration settings for SigmaForge.
"""

import os
from typing import Optional

# Default LLM model to use
DEFAULT_MODEL: str = "gpt-4o-mini"

# Default temperature for LLM calls
DEFAULT_TEMPERATURE: float = 0.2

# Maximum temperature allowed
MAX_TEMPERATURE: float = 1.0

# Minimum temperature allowed
MIN_TEMPERATURE: float = 0.0

# Request timeout in seconds
REQUEST_TIMEOUT: int = 60

# Maximum retries for LLM calls
MAX_RETRIES: int = 3

# Default author for generated Sigma rules
DEFAULT_AUTHOR: str = "SigmaForge"


def get_api_key() -> Optional[str]:
    """
    Get the OpenAI API key from environment variables.

    Returns:
        The API key if set, None otherwise.
    """
    return os.getenv("OPENAI_API_KEY")


def validate_api_key() -> bool:
    """
    Check if the OpenAI API key is configured.

    Returns:
        True if API key is set, False otherwise.
    """
    return get_api_key() is not None
