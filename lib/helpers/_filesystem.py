from lib.helpers._time import timestamp


def yield_dirs_in_dir(directory, prefix = None):
  for entry in directory.iterdir():
    if entry.is_dir():

      if prefix:
        if entry.name.startswith(prefix):
          yield entry

      else:
        yield entry


def load_file(file_path):
  with open(file_path, 'rb') as f:
    return f.read()


def write_file(file_path, data):
  with open(file_path, 'wb') as f:
    return f.write(data)


def make_output_file(output_dir, prefix = '', extension = '.txt'):
  output_file = output_dir / f"{prefix}_{str(timestamp())}.{extension}"
  return output_file


def get_cert_and_key_paths_from_dir(cert_dir):
  cert_path = cert_dir / "cert.pem"
  key_path  = cert_dir / "key.pem"
  return cert_path, key_path


def write_certs_to_output_dir(output_dir, cert_pem, key_pem, name):
  cert_dir = output_dir / name
  cert_dir.mkdir(parents=True, exist_ok=True)

  write_file(
    cert_dir / "cert.pem",
    cert_pem
  )
  write_file(
    cert_dir / "key.pem",
    key_pem
  )

  return cert_dir

