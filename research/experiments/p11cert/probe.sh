#!/bin/sh
apk add --no-cache openssl tcpdump >/dev/null 2>&1
cd /work
rm -f *.pcap
openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
  -keyout k.pem -out c.pem -subj "/CN=mail.example.test/O=SecureMailScope Probe" \
  -addext "subjectAltName=DNS:mail.example.test,DNS:imap.example.test" >/dev/null 2>&1
# start server FIRST and confirm it is listening
openssl s_server -accept 4443 -cert c.pem -key k.pem -tls1_2 -quiet >/dev/null 2>&1 &
SRV=$!
sleep 2
tcpdump -i lo -s 0 -U -w tls12.pcap 'tcp port 4443' >/dev/null 2>&1 &
TD=$!
sleep 2
echo "=== client handshake ==="
echo Q | openssl s_client -connect 127.0.0.1:4443 -tls1_2 2>&1 | grep -E "Protocol|Cipher|subject=|issuer=|Verify return code" | head -6
sleep 2
kill $TD 2>/dev/null; kill $SRV 2>/dev/null
sleep 1
echo "=== pcap ==="; ls -la tls12.pcap
