import logging
import certifi
import traceback

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.x509.verification import PolicyBuilder, Store
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from lib.helpers._filesystem import load_file, get_cert_and_key_paths_from_dir
from lib.helpers._time import utcnow

from cryptography import x509
from cryptography.hazmat.primitives import hashes


def number_to_colon_hex(n):
  serial_number_bytes = n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')
  serial_number_str = ":".join(f"{b:02X}" for b in serial_number_bytes)
  return serial_number_str


def load_certificate(cert_pem):
  certs = x509.load_pem_x509_certificate(cert_pem)
  return certs


def load_certificates(certchain_pem):
  certs = x509.load_pem_x509_certificates(certchain_pem)
  return certs


def load_certificates_file(cert_filepath):
  cert_data = load_file(cert_filepath)
  return load_certificates(cert_data)


def load_private_key_file(key_filepath):
  key_data  = load_file(key_filepath)
  return load_pem_private_key(key_data, password=None)


def make_name_for_cert(cert, host, port, prefix = ''):
  name = cert.fingerprint(hashes.SHA256())[0:4]
  name = f"{prefix}{name.hex()}.{host}.{port}"
  return name


def is_client_auth_enabled(cert):
  try:
    ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.EXTENDED_KEY_USAGE)
    usages = ext.value
    return ExtendedKeyUsageOID.CLIENT_AUTH in usages
  except:
    return False


def is_cert_date_valid(cert):
  now = utcnow()
  if now > cert.not_valid_before_utc and now < cert.not_valid_after_utc:
    return True
  return False


def verify_cert_chain_local(certs):

  with open(certifi.where(), "rb") as f:
    trusted_pems = f.read()

  trusted_certs = load_certificates(trusted_pems)
  store = Store(trusted_certs)

  cert  = certs[0]
  chain = certs[1:]

  builder  = PolicyBuilder().store(store)
  builder  = builder.time(utcnow())
  verifier = builder.build_client_verifier()

  try:
    verifier.verify(cert, chain)
    return True

  except:
    return False


def does_privkey_match_cert(cert, key):

  key_public  = key.public_key()
  cert_public = cert.public_key()

  return cert_public.public_numbers() == key_public.public_numbers()


def show_cert_info(cert_dir):

  try:

    cert_path, key_path = get_cert_and_key_paths_from_dir(cert_dir)

    certs = load_certificates_file(cert_path)
    cert  = certs[0]
    key   = load_private_key_file(key_path)

    # Basic info
    issuer          = cert.issuer.rfc4514_string()
    serial_number   = number_to_colon_hex(cert.serial_number)
    has_client_auth = is_client_auth_enabled(cert)
    has_valid_date  = is_cert_date_valid(cert)
    has_valid_chain = verify_cert_chain_local(certs)
    has_valid_key   = does_privkey_match_cert(cert, key)

    logging.info(f"\t Issuer:\t {issuer}")
    logging.info(f"\t Serial Number:\t {serial_number}")
    logging.info(f"\t Client Auth:\t {has_client_auth}")
    logging.info(f"\t Date valid:\t {has_valid_date}")
    logging.info(f"\t Valid chain:\t {has_valid_chain}")
    logging.info(f"\t Valid key:\t {has_valid_key}")

    # Subject
    subject = cert.subject.rfc4514_string()
    subject = subject if subject != '' else '<None>'
    logging.info(f"\t Subject:\n\t {subject}")
    # Find and print alternative subject names
    for extension in cert.extensions:
      value = extension.value

      if isinstance(value, x509.SubjectAlternativeName):
        for name in value:
          if isinstance(name, x509.DNSName):
            logging.info(f"\t DNS Name:\t {name.value}")
          elif isinstance(name, x509.IPAddress):
            logging.info(f"\t IP Address:\t {name.value}")
          elif isinstance(name, x509.RFC822Name):
            logging.info(f"\t Email:\t\t {name.value}")
          else:
            logging.info(f"\t Other Name:\t {name}")

    # Date
    logging.info(f"\t Not Before:\t {cert.not_valid_before_utc}")
    logging.info(f"\t Not After:\t {cert.not_valid_after_utc}")

    # Crypto
    public_key  = cert.public_key()
    pubkey_type = type(public_key).__name__
    pubkey_bits = f"({public_key.key_size})" if hasattr(public_key, 'key_size') else ''
    logging.info(f"\t Crypto:\t SigAlg: {cert.signature_hash_algorithm.name}, PubAlg: {pubkey_type} {pubkey_bits}")

    logging.debug("\t --------------- Additional info")
    for extension in cert.extensions:
      value = extension.value

      if isinstance(value, x509.ExtendedKeyUsage):
        for usage in value:
          logging.debug(f"\t\t Usage: {usage.dotted_string} ({usage._name})")
      
      elif isinstance(value, x509.KeyUsage):
        logging.debug(f"\t\t Digital Signature: {value.digital_signature}")
        logging.debug(f"\t\t Content Commitment: {value.content_commitment}")
        logging.debug(f"\t\t Key Encipherment: {value.key_encipherment}")
        logging.debug(f"\t\t Data Encipherment: {value.data_encipherment}")
        logging.debug(f"\t\t Key Agreement: {value.key_agreement}")
        logging.debug(f"\t\t Key Cert Sign: {value.key_cert_sign}")
        logging.debug(f"\t\t CRL Sign: {value.crl_sign}")

      elif isinstance(value, x509.CertificatePolicies):
        for policy in value:
          logging.debug(f"\t\t Policy Identifier: {policy.policy_identifier.dotted_string}")
          if policy.policy_qualifiers:
            for qualifier in policy.policy_qualifiers:
              logging.debug(f"\t\t   Qualifier: {qualifier}")

      elif isinstance(value, x509.CRLDistributionPoints):
        for dp in value:
          if dp.full_name:
            for name in dp.full_name:
              logging.debug(f"\t\t CRL Distribution Point: {name.value}")

      elif isinstance(value, x509.AuthorityInformationAccess):
        for desc in value:
          method_name = desc.access_method._name if desc.access_method._name else desc.access_method.dotted_string
          location = desc.access_location.value
          logging.debug(f"\t\t {method_name}: {location}")

      else:
        logging.debug(f"\t\t {value}")

  except Exception as e:
    logging.info(f"Failed to parse cert: {e}")
    logging.info({traceback.format_exc()})
  
