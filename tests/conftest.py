"""
Shared pytest fixtures and configuration.
"""
import sys
from pathlib import Path

# Ensure project root is on sys.path so imports work correctly
ROOT = Path(__file__).parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
