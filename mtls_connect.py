#!/usr/bin/env python3

import logging

from lib.helpers._logging import initialize_logger, set_loglevel
from lib.helpers._argparse import parse_connect_cmdline_arguments
from lib.helpers._time import utc_formatted
from lib.helpers._socket import does_server_request_cert
from lib.helpers._filesystem import yield_dirs_in_dir
from lib.helpers._http import get_response, get_response_with_appended_certs

from lib.config import USER_CERT_DIR, GEN_CERT_DIR

args = parse_connect_cmdline_arguments()

initialize_logger()
set_loglevel(args.loglevel)

logging.info("Cert generation started at %s\n" % utc_formatted())


if not does_server_request_cert(args.host, args.port):  
  exit( logging.critical("Server does not request a client cert") )

url = f"https://{args.host}:{args.port}{args.webdir}"

# Connect with user certs
working_user_cert_dirs = []
for user_cert_dir in yield_dirs_in_dir(USER_CERT_DIR):

  response_profile = get_response(user_cert_dir, url)

  if not response_profile.was_exception:
    working_user_cert_dirs.append(user_cert_dir)

  logging.info(f"{str(response_profile)}\t {user_cert_dir}")

# Connect with appended certs
if args.append:
  for working_user_cert_dir in working_user_cert_dirs:
    for simple_cert_dir in yield_dirs_in_dir(GEN_CERT_DIR, prefix = 'simple_'):

      response_profile = get_response_with_appended_certs(url, working_user_cert_dir, simple_cert_dir)
      logging.info(f"{str(response_profile)}\t {working_user_cert_dir} + {simple_cert_dir}")

# Connect with attack certs
if args.attack:
  for attack_cert_dir in yield_dirs_in_dir(GEN_CERT_DIR, prefix = 'attack_'):
    response_profile = get_response(attack_cert_dir, url)
    logging.info(f"{str(response_profile)}\t {attack_cert_dir}")


