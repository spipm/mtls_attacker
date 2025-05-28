#!/usr/bin/env python3

import concurrent.futures
import logging
import queue
import threading
import traceback

from lib.helpers._logging import initialize_logger, set_loglevel
from lib.helpers._stdin import read_batches_from_stdin
from lib.helpers._socket import does_server_request_cert
from lib.helpers._filesystem import yield_dirs_in_dir, make_output_file
from lib.helpers._http import get_response

from lib.config import STDIN_BATCH_SIZE, STDIN_MAX_PARALLEL
from lib.config import USER_CERT_DIR, OUTPUT_DIR

initialize_logger()
set_loglevel('info')


output_queue = queue.Queue()
output_file = make_output_file(OUTPUT_DIR, 'bulk_connect_output')

def output_writer():
  try:
    with open(output_file, 'a') as fout:
      while True:

        parts = output_queue.get()
        if not parts:
          break

        url, response_profile = parts

        fout.write("\n----------------------------\n")
        fout.write(f"{url}\t ->\t {response_profile.status_code}\n")

        fout.write(f"---------- Headers\n")
        for header in response_profile.headers:
          key, value = header, response_profile.headers[header]
          fout.write(f"{key}:\t {value}\n")

        fout.write(f"---------- Content\n")
        fout.write(f"{response_profile.text}\n")

  except Exception:
    traceback.print_exc()


def print_first_working_user_cert(host, port):
  try:
    if not does_server_request_cert(host, port):
      return

    url = f"https://{host}:{port}/"

    for user_cert_dir in yield_dirs_in_dir(USER_CERT_DIR):
      base_profile = get_response(None, url)
      response_profile = get_response(user_cert_dir, url)

      if response_profile.was_exception:
        continue

      msg = None

      if base_profile.was_exception and not response_profile.was_exception:
        msg = f"0\t 0\t 0\t 0\t -> {str(response_profile)}\t {user_cert_dir}\t {url}"

      elif base_profile.has_interesting_dif(response_profile):
        msg = f"{str(base_profile)}\t -> {str(response_profile)}\t {user_cert_dir}\t {url}"

      if msg:
        logging.info(msg)
        output_queue.put([url, response_profile])

      return

  except Exception as e:
    logging.warning(e)

writer_thread = threading.Thread(target=output_writer)
writer_thread.start()

executor = concurrent.futures.ThreadPoolExecutor(max_workers=STDIN_MAX_PARALLEL)

try:
  for batch in read_batches_from_stdin(STDIN_BATCH_SIZE, 2):
    futures = [executor.submit(print_first_working_user_cert, host, port) for host, port in batch]
    concurrent.futures.wait(futures)

except KeyboardInterrupt:
  executor.shutdown(wait=False, cancel_futures=True)

else:
  executor.shutdown(wait=True)

finally:
  output_queue.put(None)
  writer_thread.join()

