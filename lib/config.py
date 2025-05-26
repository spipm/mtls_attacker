from pathlib import Path

TIMEOUT = 5

STDIN_BATCH_SIZE = 160
STDIN_MAX_PARALLEL = 16

P12_PASS = "foobar"

CERT_DIR = Path('certs')
GEN_CERT_DIR = CERT_DIR / 'gen'
USER_CERT_DIR = CERT_DIR / 'user'

OUTPUT_DIR = Path('output')

# mimic browser
BASE_HEADERS = {
  "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:137.0) Gecko/20100101 Firefox/137.0",
  "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
  "Accept-Language": "en-US,en;q=0.9",
  "Accept-Encoding": "gzip, deflate, br",
  "Connection": "keep-alive",
  "Upgrade-Insecure-Requests": "1",
  "Sec-Fetch-Dest": "document",
  "Sec-Fetch-Mode": "navigate",
  "Sec-Fetch-Site": "none",
  "Sec-Fetch-User": "?1"
}
