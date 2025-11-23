"""
Unit tests for SigmaForge core functionality.
"""

import json
from unittest.mock import Mock, patch

import pytest
import yaml

from sigmaforge.core import (
    parse_threat_to_json,
    generate_sigma_rule,
    review_sigma_rule,
    rough_match_logs,
)


class TestParseThreatToJson:
    """Tests for parse_threat_to_json function."""

    def test_parse_valid_threat(self):
        """Test parsing a valid threat description."""
        mock_client = Mock()
        mock_response = json.dumps(
            {
                "logsource": {
                    "product": "windows",
                    "service": "security",
                    "category": "authentication",
                },
                "relevant_fields": ["user", "src_ip", "event_id"],
                "attack_behaviour": "Brute force SSH login attempts",
                "possible_mitre_techniques": ["T1110 - Brute Force"],
                "assumptions": ["SSH logs are available"],
            }
        )
        mock_client.chat_completion.return_value = mock_response

        result = parse_threat_to_json("Detect SSH brute force", mock_client)

        assert "logsource" in result
        assert "relevant_fields" in result
        assert "attack_behaviour" in result
        assert result["logsource"]["product"] == "windows"

    def test_parse_with_markdown_fences(self):
        """Test parsing when LLM returns JSON with markdown code fences."""
        mock_client = Mock()
        mock_response = """```json
{
    "logsource": {"product": "linux", "service": null, "category": null},
    "relevant_fields": ["user", "command"],
    "attack_behaviour": "Suspicious command execution",
    "possible_mitre_techniques": ["T1059 - Command Execution"],
    "assumptions": ["Command logging enabled"]
}
```"""
        mock_client.chat_completion.return_value = mock_response

        result = parse_threat_to_json("Detect suspicious commands", mock_client)

        assert result["logsource"]["product"] == "linux"
        assert "command" in result["relevant_fields"]

    def test_parse_invalid_json(self):
        """Test handling of invalid JSON response."""
        mock_client = Mock()
        mock_client.chat_completion.return_value = "This is not JSON"

        with pytest.raises(ValueError, match="LLM did not return valid JSON"):
            parse_threat_to_json("Some threat", mock_client)

    def test_parse_missing_required_field(self):
        """Test handling of JSON missing required fields."""
        mock_client = Mock()
        mock_response = json.dumps(
            {
                "logsource": {"product": "windows"},
                # Missing other required fields
            }
        )
        mock_client.chat_completion.return_value = mock_response

        with pytest.raises(KeyError, match="Missing required field"):
            parse_threat_to_json("Some threat", mock_client)


class TestGenerateSigmaRule:
    """Tests for generate_sigma_rule function."""

    def test_generate_valid_rule(self):
        """Test generating a valid Sigma rule."""
        mock_client = Mock()
        mock_rule = """title: Test Rule
description: A test detection rule
status: experimental
logsource:
    product: windows
detection:
    selection:
        EventID: 4624
    condition: selection
fields:
    - User
    - LogonType
falsepositives:
    - None
level: medium
tags:
    - attack.t1078"""
        mock_client.chat_completion.return_value = mock_rule

        threat_json = {
            "logsource": {"product": "windows", "service": "security", "category": None},
            "relevant_fields": ["User", "LogonType"],
            "attack_behaviour": "Test behavior",
            "possible_mitre_techniques": ["T1078"],
            "assumptions": [],
        }

        result = generate_sigma_rule(threat_json, mock_client)

        # Parse result to verify it's valid YAML
        parsed = yaml.safe_load(result)
        assert parsed["title"] == "Test Rule"
        assert "id" in parsed  # Should be added by function
        assert "author" in parsed  # Should be added by function
        assert "date" in parsed  # Should be added by function

    def test_generate_with_markdown_fences(self):
        """Test generation when LLM returns YAML with markdown fences."""
        mock_client = Mock()
        mock_rule = """```yaml
title: Test Rule
description: Test
status: experimental
logsource:
    product: linux
detection:
    selection:
        command: whoami
    condition: selection
fields:
    - command
falsepositives:
    - Admin activity
level: low
tags:
    - attack.discovery
```"""
        mock_client.chat_completion.return_value = mock_rule

        threat_json = {
            "logsource": {"product": "linux", "service": None, "category": None},
            "relevant_fields": ["command"],
            "attack_behaviour": "Test",
            "possible_mitre_techniques": [],
            "assumptions": [],
        }

        result = generate_sigma_rule(threat_json, mock_client)
        parsed = yaml.safe_load(result)
        assert parsed["title"] == "Test Rule"


class TestReviewSigmaRule:
    """Tests for review_sigma_rule function."""

    def test_review_preserves_metadata(self):
        """Test that review preserves existing rule metadata."""
        mock_client = Mock()

        original_rule = """id: 12345678-1234-1234-1234-123456789012
author: Original Author
date: 2024/01/01
title: Original Rule
description: Original description
status: experimental
logsource:
    product: windows
detection:
    selection:
        EventID: 4624
    condition: selection
fields:
    - User
falsepositives:
    - None
level: medium
tags:
    - attack.t1078"""

        improved_rule = """title: Improved Rule
description: Better description
status: stable
logsource:
    product: windows
detection:
    selection:
        EventID: 4624
        LogonType: 3
    condition: selection
fields:
    - User
    - LogonType
falsepositives:
    - Service accounts
level: high
tags:
    - attack.t1078
    - attack.lateral_movement"""

        mock_client.chat_completion.return_value = improved_rule

        threat_json = {
            "logsource": {"product": "windows", "service": "security", "category": None},
            "relevant_fields": ["User", "LogonType"],
            "attack_behaviour": "Test",
            "possible_mitre_techniques": ["T1078"],
            "assumptions": [],
        }

        result = review_sigma_rule(threat_json, original_rule, mock_client)
        parsed = yaml.safe_load(result)

        # Original metadata should be preserved
        assert parsed["id"] == "12345678-1234-1234-1234-123456789012"
        assert parsed["author"] == "Original Author"
        assert parsed["date"] == "2024/01/01"
        # Should have modified field
        assert "modified" in parsed
        # Content should be updated
        assert parsed["title"] == "Improved Rule"
        assert parsed["level"] == "high"


class TestRoughMatchLogs:
    """Tests for rough_match_logs function."""

    def test_basic_matching(self):
        """Test basic log matching functionality."""
        sigma_rule = """title: Test Rule
description: Test
logsource:
    product: linux
detection:
    selection:
        command: whoami
    condition: selection
fields:
    - command
level: low"""

        logs = [
            "user executed: whoami",
            "user executed: ls -la",
            "system: whoami command detected",
            "unrelated log entry",
        ]

        results = rough_match_logs(sigma_rule, logs)

        assert len(results) == 4
        # First log should match (contains 'whoami')
        assert results[0][1] is True
        # Second log should not match (doesn't contain 'whoami')
        assert results[1][1] is False
        # Third log should match (contains 'whoami')
        assert results[2][1] is True
        # Fourth log should not match
        assert results[3][1] is False

    def test_matching_with_wildcards(self):
        """Test matching with wildcard patterns."""
        sigma_rule = """title: Test Rule
logsource:
    product: windows
detection:
    selection:
        CommandLine: '*powershell*-enc*'
    condition: selection
level: high"""

        logs = [
            "powershell.exe -enc ABC123",
            "cmd.exe /c dir",
            "process: powershell -encodedcommand XYZ",
        ]

        results = rough_match_logs(sigma_rule, logs)

        # Logs containing both 'powershell' and 'enc' should match
        assert results[0][1] is True
        assert results[1][1] is False
        # Note: rough_match looks for literal parts, so both should be present
        assert results[2][1] is True

    def test_invalid_yaml(self):
        """Test handling of invalid YAML."""
        invalid_rule = "this is not valid: yaml: content:"

        logs = ["test log"]

        results = rough_match_logs(invalid_rule, logs)

        # Should return all logs as non-matches if rule can't be parsed
        assert len(results) == 1
        assert results[0][1] is False

    def test_empty_logs(self):
        """Test with empty log list."""
        sigma_rule = """title: Test
detection:
    selection:
        field: value
    condition: selection"""

        results = rough_match_logs(sigma_rule, [])

        assert len(results) == 0


class TestIntegration:
    """Integration tests (these would require actual LLM calls in full testing)."""

    def test_full_pipeline_mock(self):
        """Test the full pipeline with mocked LLM calls."""
        # This is a simplified integration test with mocks
        # In a real scenario, you might want to test against actual LLM responses

        mock_client = Mock()

        # Mock parse_threat_to_json
        threat_json = {
            "logsource": {"product": "windows", "service": "security", "category": None},
            "relevant_fields": ["EventID", "User"],
            "attack_behaviour": "Failed login attempts",
            "possible_mitre_techniques": ["T1110"],
            "assumptions": ["Windows event logs available"],
        }
        mock_client.chat_completion.return_value = json.dumps(threat_json)
        parsed = parse_threat_to_json("Detect brute force", mock_client)

        assert parsed == threat_json

        # Mock generate_sigma_rule
        sigma_yaml = """title: Brute Force Detection
status: experimental
logsource:
    product: windows
detection:
    selection:
        EventID: 4625
    condition: selection"""
        mock_client.chat_completion.return_value = sigma_yaml
        rule = generate_sigma_rule(parsed, mock_client)

        parsed_rule = yaml.safe_load(rule)
        assert "id" in parsed_rule
        assert parsed_rule["title"] == "Brute Force Detection"
