import tempfile
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from pathlib import Path

from lib.classes.ResponseProfile import ResponseProfile
from lib.helpers._filesystem import get_cert_and_key_paths_from_dir, load_file

from lib.config import TIMEOUT, BASE_HEADERS


def create_web_session(cert_dir = None):
  session = requests.Session()
  session.verify = False

  session.headers.update(BASE_HEADERS)

  if cert_dir:
    cert_path, key_path = get_cert_and_key_paths_from_dir(cert_dir)
    session.cert = (cert_path, key_path)

  return session


def get_response(cert_dir, url):
  session = create_web_session(cert_dir)
  try:
    probe_res = session.get(url, timeout = TIMEOUT, allow_redirects=False)
    was_exception = False

  except Exception as e:
    probe_res = str(e)
    was_exception = True

  return ResponseProfile(probe_res, was_exception)


def get_response_with_appended_certs(url, working_user_cert_dir, simple_cert_dir):
  user_cert_path, user_key_path = get_cert_and_key_paths_from_dir(working_user_cert_dir)
  simple_cert_path, simple_key_path = get_cert_and_key_paths_from_dir(simple_cert_dir)

  with tempfile.TemporaryDirectory() as tmpdir:
    tmp_path = Path(tmpdir)
    tmp_cert_path = tmp_path / "cert.pem"
    tmp_key_path  = tmp_path / "key.pem"

    with tmp_cert_path.open('wb') as f:
      f.write(load_file(user_cert_path))
      f.write(load_file(simple_cert_path))

    tmp_key_path.write_bytes(load_file(user_key_path))
    
    response_profile = get_response(tmp_path, url)

  return response_profile


