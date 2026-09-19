# Postfix (SMTP) + Dovecot (IMAP/POP3) -- two independent vendor codebases.
# Exim lives in Dockerfile.exim because both MTAs claim /usr/sbin/sendmail.
FROM alpine:3.20
RUN apk add --no-cache postfix dovecot dovecot-pop3d tcpdump openssl python3 \
 && adduser -D -h /home/testuser testuser \
 && echo "testuser:testpass" | chpasswd
WORKDIR /corpus
