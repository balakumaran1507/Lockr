"""Pytest configuration for Vaultless tests."""
import sys
from pathlib import Path

# Ensure repo root is on sys.path so `server`, `intent`, `cli` are importable
sys.path.insert(0, str(Path(__file__).parent.parent))
