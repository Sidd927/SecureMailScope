#!/bin/sh
# Generates a two-certificate chain (root CA -> leaf) over TLS 1.2, so that chain
# ORDERING and per-certificate field pairing can be measured rather than assumed.
# Also emits a deliberately weak leaf (SHA-1, RSA-1024) in a second capture, so the
# weak-algorithm rules are validated against real bytes instead of hand-written JSON.
apk add --no-cache openssl tcpdump >/dev/null 2>&1
cd /work
rm -f *.pcap *.pem *.srl

# ---- root CA ----
openssl req -x509 -newkey rsa:4096 -sha384 -days 3650 -nodes \
  -keyout ca.key -out ca.crt -subj "/CN=SecureMailScope Test Root/O=SMS Probe" >/dev/null 2>&1

# ---- strong leaf, signed by the root ----
openssl req -newkey rsa:2048 -nodes -keyout leaf.key -out leaf.csr \
  -subj "/CN=mail.example.test/O=SMS Probe" >/dev/null 2>&1
printf "subjectAltName=DNS:mail.example.test,DNS:smtp.example.test\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n" > leaf.ext
openssl x509 -req -in leaf.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out leaf.crt -days 365 -sha256 -extfile leaf.ext >/dev/null 2>&1
cat leaf.crt ca.crt > chain.pem

# ---- weak leaf: RSA-1024 + SHA-1, already expired ----
openssl req -newkey rsa:1024 -nodes -keyout weak.key -out weak.csr \
  -subj "/CN=legacy.example.test/O=SMS Probe" >/dev/null 2>&1
openssl x509 -req -in weak.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out weak.crt -days 1 -sha1 >/dev/null 2>&1

run() {   # $1=name $2=cert $3=key $4=extra s_server args
  openssl s_server -accept 4443 -cert "$2" -key "$3" -tls1_2 -quiet $4 >/dev/null 2>&1 &
  SRV=$!; sleep 2
  tcpdump -i lo -s 0 -U -w "$1.pcap" 'tcp port 4443' >/dev/null 2>&1 &
  TD=$!; sleep 2
  echo "=== $1 ==="
  echo Q | openssl s_client -connect 127.0.0.1:4443 -tls1_2 2>&1 \
    | grep -E "Protocol|Cipher|^subject=|^issuer=|Verify return code" | head -8
  sleep 2; kill $TD 2>/dev/null; kill $SRV 2>/dev/null; sleep 1
}

run tls12_chain_rsa2048 leaf.crt leaf.key "-cert_chain ca.crt"
run tls12_weak_sha1_rsa1024 weak.crt weak.key ""

echo "=== results ==="; ls -la *.pcap
