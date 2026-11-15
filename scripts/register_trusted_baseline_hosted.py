#!/usr/bin/env python3
"""Dedicated maintainer-reviewed Hosted entry; no authorization override flags."""
import json
from pathlib import Path
import sys

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))


if __name__ == '__main__':
    try:
        from src.hosted_registration import main
    except Exception:
        print(json.dumps({'status': 'BLOCKED', 'reason': 'HOSTED_RUNTIME_UNAVAILABLE',
                          'registry_committed': False, 'production_promotion': 'NOT_AUTHORIZED'}))
        raise SystemExit(1)
    raise SystemExit(main())
