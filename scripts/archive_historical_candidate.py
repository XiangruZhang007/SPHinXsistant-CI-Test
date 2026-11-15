#!/usr/bin/env python3
"""Reviewed Hosted entry point; no command-line authorization overrides."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.historical_candidate_archive import main

if __name__ == '__main__':
    raise SystemExit(main())
