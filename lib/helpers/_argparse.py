import argparse

from lib.config import P12_PASS


def create_default_cmdline_argument_parser(prog, description):
  parser = argparse.ArgumentParser(prog=prog, description=description)

  # Testing and logging
  parser.add_argument(
    '-l', '--loglevel',
    choices=['debug', 'info', 'error', 'stfu'],
    default='info',
    help="Change debug level (default is info)"
  )

  # Target
  parser.add_argument(
    '-p', '--port',
    type=int,
    default=443,
    help="Port number"
  )
  parser.add_argument('host',
    type=str,
    help='Target server (hostname)'
  )

  return parser


def parse_certgen_cmdline_arguments():

  parser = create_default_cmdline_argument_parser(
    prog='mtls_cert_generator',
    description='Generates certs and headers for testing mTLS'
  )

  parser.add_argument(
    '--headers',
    action='store_true',
    default=False,
    help="Output certs as headers"
  )
  parser.add_argument(
    '--certfiles',
    action='store_true',
    default=False,
    help="Output certs as files"
  )
  parser.add_argument(
    '--onlysimple',
    action='store_true',
    default=False,
    help="Only generate (2) simple certs"
  )

  # Output
  parser.add_argument(
    '--cn',
    type=str,
    default=None,
    help="Override CN for simple certs"
  )
  parser.add_argument(
    '--callback',
    type=str,
    default=None,
    help="Set CRL and OSCP fields with a callback URL"
  )

  args = parser.parse_args()

  return args


def parse_connect_cmdline_arguments():

  parser = create_default_cmdline_argument_parser(
    prog='mtls_connect',
    description='Tries to connect to mTLS service with certs'
  )

  parser.add_argument(
    '--webdir',
    type=str,
    default='/',
    help="Specify web directory"
  )
  parser.add_argument(
    '--append',
    action='store_true',
    default=False,
    help="Try appending a cloned cert to a working cert"
  )
  parser.add_argument(
    '--attack',
    action='store_true',
    default=False,
    help="Try connecting with generated attack certs"
  )

  args = parser.parse_args()

  return args

