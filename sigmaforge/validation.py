"""
Enhanced validation for Sigma rules using pySigma and static quality checks.
"""

import logging
from typing import List, Tuple

import yaml
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError

logger = logging.getLogger(__name__)


def validate_sigma_rule(sigma_yaml: str) -> Tuple[bool, List[str], List[str]]:
    """
    Validate a Sigma rule using pySigma and perform additional quality checks.

    Args:
        sigma_yaml: A Sigma rule in YAML format.

    Returns:
        A tuple of (is_valid, errors, warnings):
        - is_valid: True if the rule is valid, False otherwise
        - errors: List of error messages (empty if valid)
        - warnings: List of warning messages (quality suggestions)
    """
    errors: List[str] = []
    warnings: List[str] = []

    # Step 1: Validate YAML syntax
    try:
        rule_data = yaml.safe_load(sigma_yaml)
    except yaml.YAMLError as e:
        errors.append(f"Invalid YAML syntax: {str(e)}")
        return False, errors, warnings

    # Handle list of rules (take first one)
    if isinstance(rule_data, list):
        if not rule_data:
            errors.append("YAML contains an empty list")
            return False, errors, warnings
        rule = rule_data[0]
    else:
        rule = rule_data

    # Step 2: Validate with pySigma
    try:
        SigmaCollection.from_yaml(sigma_yaml)
        logger.info("Sigma rule passed pySigma validation")
    except SigmaError as e:
        errors.append(f"Sigma validation error: {str(e)}")
        return False, errors, warnings
    except Exception as e:
        errors.append(f"Unexpected validation error: {str(e)}")
        return False, errors, warnings

    # Step 3: Quality checks (warnings, not errors)

    # Check for tags
    if not rule.get("tags"):
        warnings.append(
            "Rule has no tags. Consider adding MITRE ATT&CK technique tags "
            "(e.g., 'attack.t1078' for Valid Accounts)."
        )
    else:
        # Check if tags include MITRE ATT&CK techniques
        tags = rule.get("tags", [])
        has_attack_tag = any(tag.startswith("attack.t") for tag in tags)
        if not has_attack_tag:
            warnings.append(
                "Rule tags don't include MITRE ATT&CK technique IDs. "
                "Consider adding tags like 'attack.t1078' or 'attack.t1059'."
            )

    # Check for description
    if not rule.get("description"):
        warnings.append(
            "Rule has no description field. Adding a description helps others "
            "understand the purpose and context of this detection."
        )

    # Check detection section
    detection = rule.get("detection", {})
    if not detection:
        errors.append("Rule has no detection section")
        return False, errors, warnings

    # Check for overly broad wildcards
    _check_wildcards(detection, warnings)

    # Check for level field
    if not rule.get("level"):
        warnings.append(
            "Rule has no 'level' field (e.g., low, medium, high, critical). "
            "This helps prioritize alerts in a SIEM."
        )

    # Check for falsepositives field
    if not rule.get("falsepositives"):
        warnings.append(
            "Rule has no 'falsepositives' field. Documenting known false positives "
            "helps analysts tune the rule effectively."
        )

    # If we made it here, the rule is valid
    logger.info(f"Validation complete: valid={True}, {len(warnings)} warnings")
    return True, errors, warnings


def _check_wildcards(detection: dict, warnings: List[str]) -> None:
    """
    Recursively check detection section for overly broad wildcard usage.

    Mutates the warnings list in-place.
    """
    def _traverse(obj):
        """Recursively traverse detection structure."""
        if isinstance(obj, dict):
            for key, value in obj.items():
                _traverse(value)
        elif isinstance(obj, list):
            for item in obj:
                _traverse(item)
        elif isinstance(obj, str):
            # Check for wildcard-only values or very short patterns
            if obj.strip() == "*":
                warnings.append(
                    "Detection contains wildcard-only value ('*'). "
                    "This may produce excessive false positives."
                )
            elif obj.count("*") >= 3:
                warnings.append(
                    f"Detection contains value with many wildcards: '{obj}'. "
                    "This may be too broad and produce noise."
                )

    _traverse(detection)
