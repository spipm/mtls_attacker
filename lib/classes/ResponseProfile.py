import difflib


INTEREST_TRESHHOLD = 0.8

lame_headers = [
  'date',
  'connection',
  'apigw-requestid',
  'cf-ray',
  'x-ray-id',
  'x-runtime',
  'x-request-id',
  'x-transaction-id',
  'x-reference-error',
  'x-correlation-id',
  'x-amz-requestid',
  'x-request-start',
  'x-ms-middleware-request-id',
  'x-akamai-request-id',
  'x-parent-response-time',
  'x-origin-response-time',
  'x-amz-cf-id',
  'redox-trace-id',
  'etag',
  'paypal-debug-id',
  'content-length',
  'server-timing',
  'akamai-grn',
]

class ResponseProfile():
  def __init__(self, requests_response, was_exception = False):
    self.was_exception = was_exception

    if was_exception:
      self.status_code = 0
      self.headers = {}
      self.text = requests_response

    else:
      self.status_code = requests_response.status_code
      self.headers = requests_response.headers
      self.text = requests_response.text


  def get_content_length(self):
    return self.headers.get('Content-Length', -1)


  def __str__(self):
    if self.was_exception:
      ret = f"0\t {self.text}"
    else:
      ret = f"1\t {self.status_code}\t {len(self.headers)}\t {self.get_content_length()}"
    return ret


  def find_header_key_difs(self, other_headers):
    differences = 0
    for dif in self.yield_header_difs(other_headers):
      differences += 1
    return differences


  def get_cookie_names(self, cookie_header):
    return {cookie.split('=')[0].strip() for cookie in cookie_header.split(';')}


  def yield_header_difs(self, other_headers):
    keys = set(self.headers.keys()).union(other_headers.keys())
    for key in keys:
      if key.lower() in lame_headers:
        continue

      if key == 'Set-Cookie':
        # For cookies only check cookie names
        self_cookies = self.get_cookie_names(self.headers.get(key, ''))
        other_cookies = self.get_cookie_names(other_headers.get(key, ''))
        if self_cookies != other_cookies:
          yield f"{key}: {self.headers.get(key)}"
        continue

      if self.headers.get(key) != other_headers.get(key):
        val1 = self.headers.get(key)
        val2 = other_headers.get(key)

        if val2 == None or val1 == None:
          if val1 == None:
            yield f"None -> {key}: {other_headers.get(key)}"
          elif val2 == None:
            yield f"{key}: {self.headers.get(key)} -> None"
          continue

        dif_ratio = difflib.SequenceMatcher(None, val1, val2).ratio()
        if dif_ratio < INTEREST_TRESHHOLD:
          yield f"{key}: {self.headers.get(key)} -> {key}: {other_headers.get(key)}"


  def compare_content_similarity(self, other_text):
    matcher = difflib.SequenceMatcher(None, self.text, other_text)
    similarity = matcher.ratio()  # 0 = identical, 1 = similar

    return similarity


  def gen_dif_properties(self, other_profile):
    have_same_status = self.status_code == other_profile.status_code
    header_keys_difs = self.find_header_key_difs(other_profile.headers)
    text_similarity = self.compare_content_similarity(other_profile.text)
    return have_same_status, header_keys_difs, text_similarity


  def has_interesting_dif(self, other_profile):
    dif_props = self.gen_dif_properties(other_profile)
    have_same_status, header_keys_difs, text_similarity = dif_props

    if have_same_status and header_keys_difs == 0 and text_similarity > INTEREST_TRESHHOLD:
      return False

    return True



