"""
Core logic for SigmaForge threat parsing and Sigma rule generation.

This module provides defensive security functionality for generating and analyzing
Sigma detection rules to help blue teams detect threats.
"""

import json
import logging
import uuid
from datetime import datetime
from typing import Any

import yaml

from sigmaforge.config import DEFAULT_AUTHOR
from sigmaforge.llm_client import LLMClient
from sigmaforge.prompts import (
    get_threat_parsing_prompt,
    get_threat_parsing_prompt_with_environment,
    get_sigma_generation_prompt,
    get_sigma_generation_prompt_with_environment,
    get_sigma_review_prompt,
    get_rule_doctor_prompt,
)

logger = logging.getLogger(__name__)


def validate_sigma_rule(sigma_yaml: str) -> tuple[bool, str | None]:
    """
    Validate a Sigma rule using the official pySigma library.

    Args:
        sigma_yaml: The Sigma rule as a YAML string.

    Returns:
        A tuple of (is_valid, error_message).
        - is_valid: True if the rule is valid, False otherwise.
        - error_message: None if valid, otherwise a string describing the error.
    """
    try:
        # Import pySigma components
        from sigma.collection import SigmaCollection
        from sigma.exceptions import SigmaError

        # Parse YAML into dict(s)
        data = list(yaml.safe_load_all(sigma_yaml))

        # Validate using SigmaCollection
        SigmaCollection.from_dicts(data)

        logger.info("Sigma rule passed pySigma validation")
        return True, None

    except SigmaError as e:
        error_msg = f"Sigma validation error: {str(e)}"
        logger.warning(error_msg)
        return False, error_msg
    except Exception as e:
        error_msg = f"Unexpected validation error: {str(e)}"
        logger.error(error_msg)
        return False, error_msg


def parse_threat_to_json(
    threat_text: str,
    llm_client: LLMClient,
    environment: str = "Generic Sigma"
) -> dict[str, Any]:
    """
    Parse a threat description or example logs into structured JSON.

    Args:
        threat_text: Natural language threat description or example log lines.
        llm_client: The LLM client to use for parsing.
        environment: Target SIEM environment (e.g., "Splunk", "Elastic", "Microsoft Sentinel").

    Returns:
        A dictionary containing structured threat information with keys:
        - logsource: dict with product, service, category
        - relevant_fields: list of field names
        - attack_behaviour: str description
        - possible_mitre_techniques: list of technique strings
        - assumptions: list of assumption strings

    Raises:
        ValueError: If the LLM response is not valid JSON.
        KeyError: If required fields are missing from the parsed JSON.
    """
    logger.info(f"Parsing threat description to structured JSON (target: {environment})")

    system_prompt = get_threat_parsing_prompt_with_environment(environment)
    response = llm_client.chat_completion(system_prompt, threat_text)

    # Clean up response - remove markdown code fences if present
    cleaned_response = response.strip()
    if cleaned_response.startswith("```"):
        lines = cleaned_response.split("\n")
        # Remove first and last lines if they're code fences
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        cleaned_response = "\n".join(lines)

    try:
        threat_json = json.loads(cleaned_response)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON from LLM response: {e}")
        logger.error(f"Response was: {cleaned_response[:500]}")
        raise ValueError(f"LLM did not return valid JSON: {e}")

    # Validate required fields
    required_fields = [
        "logsource",
        "relevant_fields",
        "attack_behaviour",
        "possible_mitre_techniques",
        "assumptions",
    ]
    for field in required_fields:
        if field not in threat_json:
            raise KeyError(f"Missing required field in threat JSON: {field}")

    logger.info("Successfully parsed threat to JSON")
    return threat_json


def generate_sigma_rule(
    threat_json: dict[str, Any],
    llm_client: LLMClient,
    environment: str = "Generic Sigma"
) -> str:
    """
    Generate a Sigma detection rule from structured threat information.

    Args:
        threat_json: Structured threat information (output from parse_threat_to_json).
        llm_client: The LLM client to use for generation.
        environment: Target SIEM environment (e.g., "Splunk", "Elastic", "Microsoft Sentinel").

    Returns:
        A complete Sigma rule as a YAML string.

    Raises:
        ValueError: If the LLM response is not valid YAML.
    """
    logger.info(f"Generating Sigma rule from threat JSON (target: {environment})")

    # Convert threat_json to a readable prompt for the LLM
    threat_description = json.dumps(threat_json, indent=2)
    user_message = f"""Generate a Sigma detection rule based on this threat information:

{threat_description}

Remember to output ONLY the Sigma YAML rule, with no markdown fences or additional text."""

    system_prompt = get_sigma_generation_prompt_with_environment(environment)
    response = llm_client.chat_completion(system_prompt, user_message)

    # Clean up response - remove markdown code fences if present
    cleaned_response = response.strip()
    if cleaned_response.startswith("```"):
        lines = cleaned_response.split("\n")
        # Remove first and last lines if they're code fences
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        cleaned_response = "\n".join(lines)

    # Parse YAML to validate it
    try:
        rule_dict = yaml.safe_load(cleaned_response)
    except yaml.YAMLError as e:
        logger.error(f"Failed to parse YAML from LLM response: {e}")
        logger.error(f"Response was: {cleaned_response[:500]}")
        raise ValueError(f"LLM did not return valid YAML: {e}")

    # Add metadata fields that we manage programmatically
    rule_dict["id"] = str(uuid.uuid4())
    rule_dict["author"] = DEFAULT_AUTHOR
    rule_dict["date"] = datetime.now().strftime("%Y/%m/%d")

    # Convert back to YAML string
    final_yaml = yaml.dump(rule_dict, default_flow_style=False, sort_keys=False)

    logger.info("Successfully generated Sigma rule")
    return final_yaml


def review_sigma_rule(
    threat_json: dict[str, Any], sigma_yaml: str, llm_client: LLMClient
) -> str:
    """
    Review and improve a Sigma detection rule.

    Args:
        threat_json: The original threat information.
        sigma_yaml: The current Sigma rule as YAML string.
        llm_client: The LLM client to use for review.

    Returns:
        An improved Sigma rule as a YAML string.

    Raises:
        ValueError: If the LLM response is not valid YAML.
    """
    logger.info("Reviewing and improving Sigma rule")

    # Parse the existing rule to preserve metadata
    try:
        existing_rule = yaml.safe_load(sigma_yaml)
        rule_id = existing_rule.get("id")
        author = existing_rule.get("author")
        date = existing_rule.get("date")
    except yaml.YAMLError:
        logger.warning("Could not parse existing rule, will generate new metadata")
        rule_id = None
        author = None
        date = None

    threat_description = json.dumps(threat_json, indent=2)
    user_message = f"""Review and improve this Sigma rule.

Original threat information:
{threat_description}

Current Sigma rule:
{sigma_yaml}

Provide an improved version of the rule. Output ONLY the improved Sigma YAML, with no markdown fences or additional text."""

    system_prompt = get_sigma_review_prompt()
    response = llm_client.chat_completion(system_prompt, user_message)

    # Clean up response
    cleaned_response = response.strip()
    if cleaned_response.startswith("```"):
        lines = cleaned_response.split("\n")
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        cleaned_response = "\n".join(lines)

    # Parse YAML
    try:
        improved_rule = yaml.safe_load(cleaned_response)
    except yaml.YAMLError as e:
        logger.error(f"Failed to parse improved rule YAML: {e}")
        raise ValueError(f"LLM did not return valid YAML: {e}")

    # Preserve or add metadata
    improved_rule["id"] = rule_id or str(uuid.uuid4())
    improved_rule["author"] = author or DEFAULT_AUTHOR
    improved_rule["date"] = date or datetime.now().strftime("%Y/%m/%d")
    improved_rule["modified"] = datetime.now().strftime("%Y/%m/%d")

    # Convert back to YAML
    final_yaml = yaml.dump(improved_rule, default_flow_style=False, sort_keys=False)

    logger.info("Successfully reviewed and improved Sigma rule")
    return final_yaml


def rough_match_logs(sigma_yaml: str, raw_logs: list[str]) -> list[tuple[str, bool]]:
    """
    Perform a rough match of log lines against a Sigma rule.

    This is a SIMPLIFIED matching function for demonstration purposes.
    It extracts literal values from the Sigma rule's selection and checks
    if each log line contains all of them.

    This is NOT a full Sigma engine and will have limitations.

    Args:
        sigma_yaml: The Sigma rule as a YAML string.
        raw_logs: List of raw log lines to check.

    Returns:
        List of tuples (log_line, matched) where matched is True if the
        log line appears to match the rule's selection criteria.
    """
    logger.info(f"Performing rough match on {len(raw_logs)} log lines")

    try:
        rule = yaml.safe_load(sigma_yaml)
    except yaml.YAMLError as e:
        logger.error(f"Failed to parse Sigma rule for matching: {e}")
        # Return all as non-matches if we can't parse the rule
        return [(log, False) for log in raw_logs]

    # Extract literal values from detection selections
    detection = rule.get("detection", {})
    literals = set()

    def extract_literals(obj: Any) -> None:
        """Recursively extract string literals from detection object."""
        if isinstance(obj, dict):
            for value in obj.values():
                extract_literals(value)
        elif isinstance(obj, list):
            for item in obj:
                extract_literals(item)
        elif isinstance(obj, str):
            # Add the string, handling wildcards by splitting
            # For rough matching, we'll just check if all non-wildcard parts are present
            parts = obj.split("*")
            for part in parts:
                if part and len(part) > 2:  # Ignore very short parts
                    literals.add(part.lower())

    # Extract literals from all selection fields
    for key, value in detection.items():
        if key.startswith("selection"):
            extract_literals(value)

    logger.debug(f"Extracted {len(literals)} literal patterns for matching")

    # Match each log line
    results = []
    for log in raw_logs:
        log_lower = log.lower()
        # Check if all literals are present in the log line
        matched = all(literal in log_lower for literal in literals) if literals else False
        results.append((log, matched))

    matches_count = sum(1 for _, matched in results if matched)
    logger.info(f"Rough matching complete: {matches_count}/{len(raw_logs)} matched")

    return results


def explain_sigma_rule(sigma_yaml: str, llm_client: LLMClient) -> dict[str, Any]:
    """
    Explain and analyze an existing Sigma rule (Rule Doctor mode).

    This function provides a comprehensive explanation of what a Sigma rule does,
    its MITRE ATT&CK coverage, likely false positives, and tuning suggestions.
    This is a DEFENSIVE tool to help blue teams understand and improve detection rules.

    Args:
        sigma_yaml: The Sigma rule as a YAML string.
        llm_client: The LLM client to use for analysis.

    Returns:
        A dictionary with keys:
        - attack_behaviour: str - Natural language explanation of what the rule detects
        - logsource_summary: str - Explanation of log sources
        - likely_false_positives: list[str] - Scenarios that might cause false positives
        - coverage: list[str] - MITRE ATT&CK techniques covered
        - tuning_suggestions: list[str] - Specific recommendations to improve the rule

    Raises:
        ValueError: If the Sigma YAML is invalid or LLM response is not valid JSON.
    """
    logger.info("Analyzing Sigma rule with Rule Doctor")

    # First validate that the YAML parses
    try:
        rule_dict = yaml.safe_load(sigma_yaml)
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid Sigma YAML: {e}")

    # Create the user message with the rule
    user_message = f"""Analyze this Sigma detection rule:

{sigma_yaml}

Provide a comprehensive explanation following the required JSON format."""

    system_prompt = get_rule_doctor_prompt()
    response = llm_client.chat_completion(system_prompt, user_message)

    # Clean up response - remove markdown code fences if present
    cleaned_response = response.strip()
    if cleaned_response.startswith("```"):
        lines = cleaned_response.split("\n")
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        cleaned_response = "\n".join(lines)

    # Parse JSON response
    try:
        explanation = json.loads(cleaned_response)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON from Rule Doctor response: {e}")
        logger.error(f"Response was: {cleaned_response[:500]}")
        raise ValueError(f"LLM did not return valid JSON: {e}")

    # Validate required fields
    required_fields = [
        "attack_behaviour",
        "logsource_summary",
        "likely_false_positives",
        "coverage",
        "tuning_suggestions",
    ]
    for field in required_fields:
        if field not in explanation:
            raise ValueError(f"Missing required field in Rule Doctor response: {field}")

    logger.info("Successfully analyzed Sigma rule")
    return explanation
