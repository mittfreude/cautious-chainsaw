"""
Convert Sigma rules to SIEM-specific query formats using pySigma.
"""

import logging
from typing import List, Tuple

from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend
from sigma.backends.elasticsearch import LuceneBackend
from sigma.pipelines.splunk import splunk_windows_pipeline
from sigma.exceptions import SigmaError

logger = logging.getLogger(__name__)


def sigma_to_splunk_queries(sigma_yaml: str) -> Tuple[bool, List[str], str]:
    """
    Convert a Sigma rule YAML string into Splunk SPL queries using pySigma.

    Args:
        sigma_yaml: A Sigma rule in YAML format.

    Returns:
        A tuple of (success, queries, error_message):
        - success: True if conversion succeeded, False otherwise
        - queries: List of Splunk SPL query strings (empty if error)
        - error_message: Error description (empty if success)
    """
    try:
        # Parse YAML into SigmaCollection
        collection = SigmaCollection.from_yaml(sigma_yaml)

        # Create pipeline and backend for Splunk
        pipeline = splunk_windows_pipeline()
        backend = SplunkBackend(processing_pipeline=pipeline)

        # Convert to Splunk queries
        queries = backend.convert(collection)

        logger.info(f"Successfully converted Sigma rule to {len(queries)} Splunk query(ies)")
        return True, queries, ""

    except SigmaError as e:
        logger.error(f"Sigma conversion error: {e}")
        return False, [], f"Sigma conversion error: {str(e)}"
    except Exception as e:
        logger.error(f"Unexpected error during Splunk conversion: {e}")
        return False, [], f"Conversion error: {str(e)}"


def sigma_to_elasticsearch_queries(sigma_yaml: str) -> Tuple[bool, List[str], str]:
    """
    Convert a Sigma rule YAML string into Elasticsearch (Lucene) queries using pySigma.

    Args:
        sigma_yaml: A Sigma rule in YAML format.

    Returns:
        A tuple of (success, queries, error_message):
        - success: True if conversion succeeded, False otherwise
        - queries: List of Elasticsearch query strings (empty if error)
        - error_message: Error description (empty if success)
    """
    try:
        # Parse YAML into SigmaCollection
        collection = SigmaCollection.from_yaml(sigma_yaml)

        # Create backend for Elasticsearch (Lucene syntax)
        backend = LuceneBackend()

        # Convert to Elasticsearch queries
        queries = backend.convert(collection)

        logger.info(f"Successfully converted Sigma rule to {len(queries)} Elasticsearch query(ies)")
        return True, queries, ""

    except SigmaError as e:
        logger.error(f"Sigma conversion error: {e}")
        return False, [], f"Sigma conversion error: {str(e)}"
    except Exception as e:
        logger.error(f"Unexpected error during Elasticsearch conversion: {e}")
        return False, [], f"Conversion error: {str(e)}"
