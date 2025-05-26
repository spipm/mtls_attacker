


Final design

I first tried to make a script that would do headers, connect, cert appending, cert fuzzing, etc, but it just became too much. If the code looks a bit weird it's because I first wrote it with AI in Python, then I rewrote it in python myself, then tried to make an nmap plugin, then I let AI write parts in bash, then some parts were ported from my first python project to bash with AI, when I let AI convert parts back to python. Finally I made actual design choices with the lessons I learned (like to never write things with AI in the lead) and wrote everything myself.

- create a custom dir ca_certs where you put your own p12s
  - these will be called ca_ certs

- a cert generation script, which generates p12s and pems. Note that all generated certs are self-signed.
  - simple_ certs are just copies of the server cert (client and server) with guessed valid CNs. Use the options --cn and --dn to set a custom values. Use the --callback option to add a callback URL in the CRL and OSCP fields.
  - attack_ are certs with payloads in the cn and dn fields. These are the same as the simple_ but with payloads in them. So you can use the same options to set custom values.

  - a --header option for an http-header generation script, which uses all of the above certs in common cert headers. See the file TODO for a list of headers you can use to fuzz in intruder. You can also use those headers to add payloads that can't be set in a regular cert, like the serial number.


- a script to parse nmap results so they work with the detector script
- a detector script that finds mtls-services
- a connect script to connect with all the certs from a directory. Use the --append flag to append certs from simple_ to every cert that can connect to check for a parsing bypass. Use the --attack flag to try to connect with all the certs that contain payloads.

Once you can connect with certs, you can use the generation script to create custom certs, or you can try application-layer vulns, or fuzz the headers from the headers readme.



There are just so many fields that might be parsed incorrectly it's insane