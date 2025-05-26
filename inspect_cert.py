#!/usr/bin/env python3

import sys
from pathlib import Path

from lib.helpers._cert_parsing import show_cert_info
from lib.helpers._logging import initialize_logger, set_loglevel

INPUT_DIR = sys.argv[1] if len(sys.argv) > 1 else None
if not INPUT_DIR:
  print(f"Usage: ./print_cert.py <cert_dir or base64>")
  sys.exit(1)

initialize_logger()
set_loglevel('debug')

show_cert_info(Path(INPUT_DIR))

