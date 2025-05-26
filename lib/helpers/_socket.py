import ssl
import socket
import subprocess

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from lib.config import TIMEOUT


def obtain_server_cert(host, port, timeout=TIMEOUT):

  context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
  context.check_hostname = False
  context.verify_mode = ssl.CERT_NONE

  cert = None
  
  try:
    raw_sock = socket.create_connection((host, port), timeout=timeout)
    tls_sock = context.wrap_socket(raw_sock, server_hostname=host)
    der_cert = tls_sock.getpeercert(binary_form=True)
    cert = x509.load_der_x509_certificate(der_cert, default_backend())

  except Exception as e:
    pass

  return cert


def does_server_request_cert(host, port):
  url = f"https://{host}:{port}/"

  # Optional throttling
  # time.sleep(0.5)

  try:
    result = subprocess.run(
      ["curl", "-vk", url],
      stderr=subprocess.STDOUT, stdout=subprocess.PIPE,
      timeout=TIMEOUT,
      text=False  # capture as bytes
    )
    output = result.stdout

    if b"Request CERT" in output:
      return True
      
  except subprocess.TimeoutExpired:
    pass
  except Exception as e:
    print(f"Error checking {host}:{port} - {e}", file=sys.stderr)

