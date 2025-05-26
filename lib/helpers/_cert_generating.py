from cryptography import x509
from cryptography.x509 import RFC822Name
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import OtherName, ObjectIdentifier
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import (
  NameOID,
  ExtendedKeyUsageOID,
  AuthorityInformationAccessOID,
  ObjectIdentifier,
)
from cryptography.x509.general_name import DNSName, UniformResourceIdentifier
from asn1crypto import core

import warnings
from cryptography.utils import CryptographyDeprecationWarning
#  Supress "CryptographyDeprecationWarning: Parsed a serial number which wasn't positive (i.e., it was negative or zero),
#  which is disallowed by RFC 5280. Loading this certificate will cause an exception in a future release of cryptography."
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)


from lib.helpers._time import cert_date_yesterday, cert_date_add_year


def is_email(email):
  return '@' in email


def username_from_email(email):
  return email.split('@')[0]


def new_private_key():
  return rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
  )


def make_san(name):
  return x509.SubjectAlternativeName([
    name
  ])


def make_cloned_subject_with_cn(subject, cn):
  name = x509.NameAttribute(NameOID.COMMON_NAME, cn)
  new_attributes = []
  for attribute in subject:
    if attribute.oid == NameOID.COMMON_NAME:
      new_attributes.append(name)
    else:
      new_attributes.append(attribute)
  return x509.Name(new_attributes)


def make_empty_subject_with_cn(cn):
  name = x509.NameAttribute(NameOID.COMMON_NAME, cn)
  return x509.Name([name])


def make_fake_ca_issuer():
  # LetsEncrypt CA
  return x509.Name([
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Internet Security Research Group"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"ISRG Root X1"),
  ])


def make_aia(callback_uri):
  return x509.AuthorityInformationAccess([
    x509.AccessDescription(
      AuthorityInformationAccessOID.OCSP,
      callback_uri
    ),
    x509.AccessDescription(
      AuthorityInformationAccessOID.CA_ISSUERS,
      callback_uri
    )
  ])


def make_crl_distribution_points(callback_uri):
  return x509.CRLDistributionPoints([
    x509.DistributionPoint(
      full_name=[callback_uri],
      relative_name=None,
      reasons=None,
      crl_issuer=[callback_uri]
    )
  ])


def make_fresh_crl(callback_uri):
  return x509.FreshestCRL([
    x509.DistributionPoint(
      full_name=[callback_uri],
      relative_name=None,
      reasons=None,
      crl_issuer=None
    )
  ])


def key_to_bytes(key):
  return key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption(),
  )


def cert_and_key_to_pems(cert, key):
  cert_pem = cert.public_bytes(serialization.Encoding.PEM)
  key_pem = key_to_bytes(key)

  return cert_pem, key_pem


def make_generic_client_cert_builder():
  # Generic client cert
  builder = (
    x509.CertificateBuilder()
    .add_extension(
      x509.BasicConstraints(ca=False, path_length=None),
      critical=True
    ).add_extension(
      x509.KeyUsage(
        digital_signature=True,
        key_encipherment=True,
        key_agreement=True,
        content_commitment=False,
        data_encipherment=False,
        key_cert_sign=False,
        encipher_only=False,
        decipher_only=False,
        crl_sign=False,
      ),
      critical=True
    ).add_extension(
      x509.ExtendedKeyUsage([
        ExtendedKeyUsageOID.CLIENT_AUTH
      ]),
      critical=False
    )
  )
  return builder


def make_client_cert(server_cert_to_clone, hostname, cn, type = 'user', callback = None):
  key = new_private_key()

  ## Create values for this cert

  if cn == None:
    if type == 'user':
      cn = "admin"
      san = RFC822Name(f"{cn}@{hostname}")
    else:
      cn = f"localhost.{hostname}"
      san = DNSName(cn)

  else:
    try:
      if is_email(cn):
        san = RFC822Name(cn)
        cn = username_from_email(cn)
      else:
        san = DNSName(cn)
    except:
      cn_pem = core.UTF8String(cn).dump()
      san = OtherName(ObjectIdentifier("1.3.6.1.4.1.1337.1"), cn_pem) # OtherName as (invalid) fallback

  san = make_san(san)

  if server_cert_to_clone:
    subject = server_cert_to_clone.subject
    subject = make_cloned_subject_with_cn(subject, cn)
    issuer = server_cert_to_clone.issuer
    serial = server_cert_to_clone.serial_number

  else:
    subject = make_empty_subject_with_cn(cn)
    issuer = make_fake_ca_issuer()
    serial = 172886928669790476064670243504169061120 # LetsEncrypt root CA serial

  ## Build cert base

  cert_builder = make_generic_client_cert_builder()
  cert_builder = (
    cert_builder.subject_name(subject)
    .issuer_name(issuer)
    .public_key(key.public_key())
    .serial_number(serial)
    .not_valid_before(cert_date_yesterday())
    .not_valid_after(cert_date_add_year())
  )

  ## Add callback

  if callback:
    callback_uri = UniformResourceIdentifier(callback)
    
    aia = make_aia(callback_uri)
    freshcrl = make_fresh_crl(callback_uri)
    crldist = make_crl_distribution_points(callback_uri)

    cert_builder = (
      cert_builder.add_extension(aia, critical=False)
      .add_extension(crldist, critical=False)
      .add_extension(freshcrl, critical=False)
    )

  ## Add SAN

  cert_builder = cert_builder.add_extension(
    x509.SubjectAlternativeName(san),
    critical=False
  )

  ## Sign and return

  cert = cert_builder.sign(private_key=key, algorithm=hashes.SHA256())
  return cert, key


