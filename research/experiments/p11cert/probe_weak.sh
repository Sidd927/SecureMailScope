#!/bin/sh
apk add --no-cache openssl tcpdump >/dev/null 2>&1
cd /work
rm -f tls12_weak_sha1_rsa1024.pcap
# OpenSSL 3.x refuses SHA-1 signatures and RSA-1024 at the default security level,
# so both ends are explicitly lowered. This is a deliberately weak fixture.
openssl req -newkey rsa:1024 -nodes -keyout weak.key -out weak.csr \
  -subj "/CN=legacy.example.test/O=SMS Probe" 2>&1 | tail -2
openssl x509 -req -in weak.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out weak.crt -days 365 -sha1 2>&1 | tail -2
openssl x509 -in weak.crt -noout -subject -issuer -dates 2>&1 | head -4
openssl s_server -accept 4444 -cert weak.crt -key weak.key -tls1_2 -quiet \
  -cipher 'ALL:@SECLEVEL=0' -security_debug >/dev/null 2>&1 &
SRV=$!; sleep 2
tcpdump -i lo -s 0 -U -w tls12_weak_sha1_rsa1024.pcap 'tcp port 4444' >/dev/null 2>&1 &
TD=$!; sleep 2
echo Q | openssl s_client -connect 127.0.0.1:4444 -tls1_2 -cipher 'ALL:@SECLEVEL=0' 2>&1 \
  | grep -E "Protocol|Cipher|^subject=|^issuer=|Verify return|error" | head -8
sleep 2; kill $TD 2>/dev/null; kill $SRV 2>/dev/null; sleep 1
ls -la tls12_weak_sha1_rsa1024.pcap
