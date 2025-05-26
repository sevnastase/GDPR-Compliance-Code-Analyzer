# This file contains utility functions that assist with various tasks in the project.

import logging

def setup_logging(log_level=logging.INFO):
    """Set up logging configuration."""
    logging.basicConfig(level=log_level,
                        format='%(asctime)s - %(levelname)s - %(message)s')

def format_data(data):
    """Format data for output."""
    return str(data)

def validate_input(data, expected_type):
    """Validate input data type."""
    if not isinstance(data, expected_type):
        raise ValueError(f"Expected data of type {expected_type}, got {type(data)}")