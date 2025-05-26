#!/bin/bash

# Add your p12s (pwd foobar) do this dir and run this script
#   It will extract the certs and keys so they can be used to connect
#   Don't forget to delete your certs afterwards
#

for p12_file in *.p12; do
  [ -e "$p12_file" ] || continue

  output_dir=$(basename "$p12_file" .p12)
  mkdir -p "$output_dir"

  openssl pkcs12 -in "$p12_file" -nokeys -out "$output_dir/cert.pem" -passin pass:foobar
  openssl pkcs12 -in "$p12_file" -nocerts -nodes  -out "$output_dir/key.pem"  -passin pass:foobar

  echo "Extracted cert and key to $output_dir"
done
