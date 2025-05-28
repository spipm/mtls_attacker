## Short description

Here are some scripts you might use to test mTLS implementations. It's mostly just detecting that mTLS is used, and checking if you can connect with a CA-signed or generated cert. You have an option to generate certs with malicious payloads, to check how a server responds.

## Inspiration

This tool is mostly inspired by [this](https://github.blog/security/vulnerability-research/mtls-when-certificate-authentication-is-done-wrong/) article on mTLS issues. Multiple attack methods are described:
- A server accepting any regular CA-signed cert (instead of the CA that manages their own PKI).
- Appending another certificate to the valid chain in the hope that the server will use the last one.
- Injecting fields, like the CN, with payloads in the hope that it triggers a bug in the parser or the backend.
- Changing URL-fields (like OSCP, CRL) to callback domains in the hope that the server will make a call to them.

## Challenge

It's been a challenge to program this for some reason. It hasn't found any security issues yet, but I ran out of time I wanted to spend on this.

I first tried to make a script that would do headers, connect, cert appending, cert fuzzing, etc, but it just became too much. If the code looks a bit weird it's because I first wrote it with AI in Python, then I rewrote it in python myself, then tried to make an nmap plugin, then I let AI write parts in bash, then some parts were ported from my first python project to bash with AI, only to let AI convert parts back to python. Finally I made actual design choices with the lessons I learned (like to never write things with AI in the lead) and finally I wrote everything myself.

## Scripts

parse_nmap.py
  - Extract host and ip for open services from nmap results
  - Input: nmap output in XML format. Run with `-n` to preserve hostnames
  - Usage: `./parse_nmap.py input/nmap_output.xml > input/services.txt`
  - Output: Prints `<host> <port>` per line

inspect_cert.py
  - Show information about a cert / key pair in a dir
  - Usage: `./inspect_cert.py certs/client_web_cert`

mtls_detect.py
  - Detects if the server requests a client certificate
  - Input: stdin with `<host> <port>`
  - Usage: `cat input/services.txt | ./mtls_detect.py > input/require_certs.txt`
  - Output: Prints `<host> <port>` per line

mtls_connect_bulk.py
  - Bulk scan to try and connect with user certs. Quits on the first working cert for a host.
  - Input: stdin with `<host> <port>`
  - Usage: `cat input/require_certs.txt | ./mtls_connect_bulk.py`
  - Output: An overview of differences between a regular request (without cert) and one with a working cert

mtls_cert_generator.py
  - Generates self-signed certs to test with.
  - Input: Host information and options, see `./mtls_cert_generator.py --help`
  - Usage: `./mtls_cert_generator.py some.server.with.mtls.com --callback "http://www.spipm.nl" --headers --certfiles`
  - Output: Certificate files in certs/gen (to use with these tools), or headers in the headers dir to test the application layer with a tool like Burp.
  - Warning: Outputs a lot of certs! Don't forget to `rm -rf certs/gen/*` after a test session.

mtls_connect.py
  - Connects to a server with user certs and certs generated with mtls_cert_generation. For example, `--attack` uses all the attack scripts generates with cert_generator, and `--append` appends certs like CVE-2023-2422.
  - Input: Host information and options, see `./mtls_connect.py --help`
  - Usage: `./mtls_connect.py --attack --append some.server.with.mtls.com`
  - Output: An overview of certs and response properties (was_exception, status_code, num_headers, content_length)

## Usage

- Get one or multiple CA-signed certs. A Let's Encrypt web server cert works well (it has the Auth flag set!). Put your own p12 certs (pwd foobar) in `certs/user/` and run `./extract_certs.sh`. Example way to use `openssl` to convert a generated cert to a p12:
```
openssl pkcs12 -export -out mycert.p12 -inkey key.pem -in chain.pem -passout pass:foobar
```

- Run an nmap scan on TLS ports. Use hostnames and use the `-n` option to preserve them.
- Use `parse_nmap.py` to extract services.
- Use `mtls_detect.py` or `mtls_connect_bulk.py` to find interesting services you can connect to.
- Use `mtls_connect.py` and `mtls_cert_generation.py` to generate certs for a host and test how the server responds to different certs.

Once you can connect with certs, you can use the generation script to create custom certs, or you can try application-layer vulns, fuzz cert headers, etc.

## Using the generated headers

If you test the certificate headers with Burp, you might want to add:
```
X-SSL-Protocol: TLSv1.2
X-Client-Verify: SUCCESS
X-SSL-Client-Verify: SUCCESS
SSLClientCertStatus: SUCCESS
SSL_CLIENT_VERIFY: SUCCESS
X-SSL: 1
```
Other headers you can fuzz are:
```
X-SSL-Server-Name
X-Client-Serial
X-SSL-Client-Serial
SSLClientCertSN
Cf-Cert-Issuer-Serial
Cf-Cert-Serial
X-SSL-Client-I-Dn
Cf-Cert-Subject-Dn
X-Client-DN
X-SSL-Client-DN
X-SSL-Client-S-Dn
X-SSL-Subject
X-SSL-Client-CN
X-SSL-Server-Name
X-Client-V-Start
X-Client-V-End
X-SSL-Client-NotBefore
X-SSL-Client-NotAfter
```
For example, in 2020 Puppet had a vuln that only needed headers:
```
X-Client-Verify: True
X-Client-DN: *
X-Client-Cert: nil
X-SSL-Client-Verify: 0
```
Web paths you might try are:
```
/
/oauth/token
/oauth2/token
/oauth/introspect
/oauth/revoke
/introspect
/internal/
/api/internal/
/private/
/secure/
/v1/secure/
/admin/
/mgmt/
/partner-api/
/integration/
/client-auth
/client/certs
/certs
```

