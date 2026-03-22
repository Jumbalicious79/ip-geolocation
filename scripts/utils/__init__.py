"""
Utility functions for the project.
"""

# Common imports and utilities can go here
import os
import sys
from pathlib import Path

# Get project root directory
PROJECT_ROOT = Path(__file__).parent.parent
DATA_DIR = PROJECT_ROOT / "data"
INPUT_DIR = PROJECT_ROOT / "input"
OUTPUT_DIR = PROJECT_ROOT / "output"

def ensure_output_dir():
    """Ensure output directory exists."""
    OUTPUT_DIR.mkdir(exist_ok=True)
    
def get_input_file(filename):
    """Get path to input file."""
    return INPUT_DIR / filename
    
def get_output_file(filename):
    """Get path to output file."""
    ensure_output_dir()
    return OUTPUT_DIR / filename
