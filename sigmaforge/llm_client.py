"""
LLM client wrapper for OpenAI API interactions.
"""

import logging
from typing import Optional

from openai import OpenAI, OpenAIError

from sigmaforge.config import (
    DEFAULT_MODEL,
    DEFAULT_TEMPERATURE,
    REQUEST_TIMEOUT,
    MAX_RETRIES,
    get_api_key,
)

logger = logging.getLogger(__name__)


class LLMClient:
    """Wrapper around OpenAI API for chat completions."""

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        temperature: float = DEFAULT_TEMPERATURE,
        api_key: Optional[str] = None,
    ):
        """
        Initialize the LLM client.

        Args:
            model: The model name to use for completions.
            temperature: Sampling temperature (0.0 to 1.0).
            api_key: OpenAI API key. If None, will be read from environment.

        Raises:
            ValueError: If API key is not provided and not found in environment.
        """
        self.model = model
        self.temperature = temperature
        self.api_key = api_key or get_api_key()

        if not self.api_key:
            raise ValueError(
                "OpenAI API key not found. Please set OPENAI_API_KEY environment variable."
            )

        self.client = OpenAI(api_key=self.api_key, timeout=REQUEST_TIMEOUT, max_retries=MAX_RETRIES)

    def chat_completion(
        self,
        system_prompt: str,
        user_message: str,
        temperature: Optional[float] = None,
    ) -> str:
        """
        Get a chat completion from the LLM.

        Args:
            system_prompt: The system prompt to set context.
            user_message: The user's message/query.
            temperature: Override the default temperature for this call.

        Returns:
            The LLM's response content as a string.

        Raises:
            OpenAIError: If the API call fails.
            ValueError: If the response is empty or invalid.
        """
        temp = temperature if temperature is not None else self.temperature

        try:
            logger.debug(f"Calling LLM with model={self.model}, temp={temp}")
            logger.debug(f"System prompt (truncated): {system_prompt[:100]}...")
            logger.debug(f"User message (truncated): {user_message[:200]}...")

            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message},
                ],
                temperature=temp,
            )

            content = response.choices[0].message.content

            if not content:
                raise ValueError("Received empty response from LLM")

            logger.debug(f"LLM response (truncated): {content[:200]}...")
            return content

        except OpenAIError as e:
            logger.error(f"OpenAI API error: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during LLM call: {e}")
            raise


def create_client(
    model: str = DEFAULT_MODEL,
    temperature: float = DEFAULT_TEMPERATURE,
) -> LLMClient:
    """
    Factory function to create an LLM client.

    Args:
        model: The model name to use.
        temperature: Sampling temperature.

    Returns:
        An initialized LLMClient instance.
    """
    return LLMClient(model=model, temperature=temperature)
