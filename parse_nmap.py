#!/usr/bin/env python3

# Extracts host and port from an nmap xml file
#  Make sure to run nmap with `-n` so it keeps the original hostnames

import sys
import xml.etree.ElementTree as ET

def print_hosts_and_ports_from_nmap_xml(xml_file):
  tree = ET.parse(xml_file)
  root = tree.getroot()
  for host in root.findall('host'):

    domain_elem = host.find('hostnames/hostname')
    domain = domain_elem.attrib['name'] if domain_elem is not None else ""

    for port_elem in host.findall('ports/port'):
      state = port_elem.find('state')

      if state is not None and state.attrib.get('state') == 'open':
        port = int(port_elem.attrib['portid'])
        print(domain, port)

INPUT_FILE = sys.argv[1] if len(sys.argv) > 1 else None

if not INPUT_FILE:
  print(f"Usage: ./parse_nmap.py <nmap_output.xml>")
  sys.exit(1)

print_hosts_and_ports_from_nmap_xml(INPUT_FILE)
