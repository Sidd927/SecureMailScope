#!/bin/sh
# Re-emits the certificate fixtures on port 465 (implicit-TLS SMTPS), so they exercise
# the real session-reconstruction path instead of only the crypto layer. The
# certificates and TLS parameters are identical to the 4443 captures.
apk add --no-cache openssl tcpdump >/dev/null 2>&1
cd /work
run() {  # $1=name $2=cert $3=key $4=extra-server-args $5=extra-client-args
  openssl s_server -accept 465 -cert "$2" -key "$3" -tls1_2 -quiet $4 >/dev/null 2>&1 &
  SRV=$!; sleep 2
  tcpdump -i lo -s 0 -U -w "$1.pcap" 'tcp port 465' >/dev/null 2>&1 &
  TD=$!; sleep 2
  echo Q | openssl s_client -connect 127.0.0.1:465 -tls1_2 $5 2>&1 \
    | grep -E "Protocol|Cipher " | head -3
  sleep 2; kill $TD 2>/dev/null; kill $SRV 2>/dev/null; sleep 1
  echo "$1: $(wc -c < "$1.pcap") bytes"
}
run smtps_tls12_selfsigned_rsa2048 c.pem k.pem "" ""
run smtps_tls12_chain_rsa2048 leaf.crt leaf.key "-cert_chain ca.crt" ""
run smtps_tls12_weak_sha1_rsa1024 weak.crt weak.key "-cipher ALL:@SECLEVEL=0" "-cipher ALL:@SECLEVEL=0"
