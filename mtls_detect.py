#!/usr/bin/env python3

import concurrent.futures

from lib.helpers._stdin  import read_batches_from_stdin
from lib.helpers._socket import does_server_request_cert

from lib.config import STDIN_BATCH_SIZE, STDIN_MAX_PARALLEL


def print_if_server_requests_cert(host, port):
  if does_server_request_cert(host, port):
    print(f"{host} {port}")

executor = concurrent.futures.ThreadPoolExecutor(max_workers=STDIN_MAX_PARALLEL)

try:
  for batch in read_batches_from_stdin(STDIN_BATCH_SIZE, 2):
    futures = [executor.submit(print_if_server_requests_cert, host, port) for host, port in batch]
    concurrent.futures.wait(futures)

except KeyboardInterrupt:
  executor.shutdown(wait=False, cancel_futures=True)

else:
  executor.shutdown(wait=True)
