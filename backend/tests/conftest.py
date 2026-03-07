"""
conftest.py — pytest root configuration.
Adds the backend/ directory to sys.path so that 'from app.xxx import ...'
works correctly from the tests/ folder without any extra setup.
"""
import sys
import os

# Insert backend/ as the first path so 'app.*' imports resolve correctly
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)
