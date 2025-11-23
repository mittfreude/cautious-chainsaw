"""
SigmaForge - LLM-assisted Sigma detection rule generator.

A defensive cybersecurity tool for SOC analysts and detection engineers.
"""

__version__ = "1.0.0"
__author__ = "SigmaForge Team"

from sigmaforge.core import (
    parse_threat_to_json,
    generate_sigma_rule,
    review_sigma_rule,
    rough_match_logs,
)

__all__ = [
    "parse_threat_to_json",
    "generate_sigma_rule",
    "review_sigma_rule",
    "rough_match_logs",
]
