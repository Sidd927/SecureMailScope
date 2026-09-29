"""
OQ-33r: capture REAL mail-server traffic inside a container.

Runs inside the sms-oq33r image. Starts a real vendor server, records the loopback with
tcpdump, drives the server with Python's own client libraries, and writes one pcap per
scenario.

Why this matters: every SecureMailScope evaluation number so far rests on captures our
own generators produced. The application bytes here are emitted by Postfix, Dovecot and
Exim -- three independently written codebases whose banners, capability ordering,
continuation style and segmentation we do not control and did not design around.

Safety: throwaway container, a single local account, synthetic message text, self-signed
test certificates, no real mail and no personal data.
"""
from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import time
from typing import Callable, Dict, List, Optional

OUT = "/corpus/out"
CERT, KEY = "/corpus/test.pem", "/corpus/test.key"


def sh(cmd: str, check: bool = False, timeout: int = 60) -> subprocess.CompletedProcess:
    """Run a shell command with a hard timeout.

    The timeout is not defensive decoration: a daemon that inherits our stdout keeps the
    pipe open, and without it `subprocess.run` waits for the daemon to exit rather than
    for the start command to return. That failure mode cost two silent runs here.
    """
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True,
                              check=check, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, "", "timeout")


def wait_port(port: int, timeout: float = 25.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1.0):
                return True
        except OSError:
            time.sleep(0.3)
    return False


class Capture:
    """tcpdump on loopback for the duration of one scenario."""

    def __init__(self, name: str, port: int) -> None:
        self.path = os.path.join(OUT, f"{name}.pcap")
        self.port = port
        self.proc: Optional[subprocess.Popen] = None

    def __enter__(self) -> "Capture":
        self.proc = subprocess.Popen(
            ["tcpdump", "-i", "lo", "-s", "0", "-U", "-w", self.path,
             f"tcp port {self.port}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.2)          # let the filter attach before traffic starts
        return self

    def __exit__(self, *exc) -> None:
        time.sleep(1.0)          # let the last packets reach the file
        if self.proc:
            self.proc.send_signal(signal.SIGTERM)
            self.proc.wait(timeout=10)


# ------------------------------------------------------------------ servers
def make_certs() -> None:
    sh(f"openssl req -x509 -newkey rsa:2048 -keyout {KEY} -out {CERT} -days 2 "
       f"-nodes -subj '/CN=mail.test.invalid'", check=True)
    sh(f"chmod 644 {KEY} {CERT}")


def start_postfix(tls: str = "may") -> None:
    """Postfix on 25. `tls` selects whether STARTTLS is offered at all."""
    sh("mkdir -p /var/spool/postfix /etc/postfix")
    sh("newaliases 2>/dev/null || true")
    conf = [
        "myhostname = mail.test.invalid",
        "mydomain = test.invalid",
        "inet_interfaces = loopback-only",
        "smtpd_banner = $myhostname ESMTP $mail_name",
        "maillog_file = /var/log/postfix.log",
        f"smtpd_tls_cert_file = {CERT}",
        f"smtpd_tls_key_file = {KEY}",
        f"smtpd_tls_security_level = {tls}",
        "smtpd_tls_auth_only = no",
        "compatibility_level = 3.6",
    ]
    if tls == "none":
        conf = [c for c in conf if not c.startswith("smtpd_tls_security_level")]
        conf.append("smtpd_tls_security_level = none")
    with open("/etc/postfix/main.cf", "w") as fh:
        fh.write("\n".join(conf) + "\n")
    sh("postfix stop 2>/dev/null; postfix start")
    wait_port(25)


def start_dovecot(protocols: str = "imap pop3", ssl: str = "yes") -> None:
    sh("mkdir -p /etc/dovecot /home/testuser/Maildir/{cur,new,tmp} "
       "&& chown -R testuser /home/testuser")
    conf = f"""
protocols = {protocols}
listen = 127.0.0.1
log_path = /var/log/dovecot.log
ssl = {ssl}
ssl_cert = <{CERT}
ssl_key = <{KEY}
disable_plaintext_auth = no
auth_mechanisms = plain login
mail_location = maildir:/home/testuser/Maildir
passdb {{
  driver = static
  args = password=testpass
}}
userdb {{
  driver = static
  args = uid=testuser gid=testuser home=/home/testuser
}}
service imap-login {{
  inet_listener imap {{
    port = 143
  }}
}}
service pop3-login {{
  inet_listener pop3 {{
    port = 110
  }}
}}
"""
    with open("/etc/dovecot/dovecot.conf", "w") as fh:
        fh.write(conf)
    # Started once per run. Dovecot is deliberately NOT restarted mid-run: reconfiguring
    # a live master reliably left the old listeners in place, which silently gave a
    # later scenario the earlier configuration -- a corpus that lies about what the
    # server offered is worse than one scenario fewer.
    sh("pkill -9 dovecot 2>/dev/null; true")
    time.sleep(1.5)
    # A SIGKILLed master leaves its pid file behind and the next start refuses with
    # "already running" while nothing is listening.
    sh("rm -f /run/dovecot/master.pid")
    sh("dovecot")
    wait_port(143)


# ------------------------------------------------------------------ clients
def smtp_starttls(port: int = 25) -> str:
    import smtplib
    with smtplib.SMTP("127.0.0.1", port, timeout=20) as c:
        c.ehlo("client.test.invalid")
        caps = dict(c.esmtp_features)
        c.starttls()
        c.ehlo("client.test.invalid")
        c.quit()
    return f"starttls ok; pre-tls caps={sorted(caps)}"


def smtp_plain(port: int = 25) -> str:
    import smtplib
    with smtplib.SMTP("127.0.0.1", port, timeout=20) as c:
        c.ehlo("client.test.invalid")
        caps = sorted(c.esmtp_features)
        c.docmd("MAIL", "FROM:<a@test.invalid>")
        c.docmd("RCPT", "TO:<testuser@test.invalid>")
        c.quit()
    return f"cleartext session; caps={caps}"


def smtp_declines(port: int = 25) -> str:
    """Server advertises STARTTLS; the client never issues it."""
    import smtplib
    with smtplib.SMTP("127.0.0.1", port, timeout=20) as c:
        c.ehlo("client.test.invalid")
        advertised = c.has_extn("starttls")
        c.quit()
    return f"client declined; advertised={advertised}"


def imap_starttls(port: int = 143) -> str:
    import imaplib
    c = imaplib.IMAP4("127.0.0.1", port)
    caps = c.capabilities
    c.starttls()
    c.login("testuser", "testpass")
    c.logout()
    return f"imap starttls ok; pre-tls caps={sorted(caps)[:6]}"


def imap_plain(port: int = 143) -> str:
    import imaplib
    c = imaplib.IMAP4("127.0.0.1", port)
    caps = sorted(c.capabilities)
    c.login("testuser", "testpass")
    c.logout()
    return f"imap cleartext login; caps={caps[:6]}"


def pop3_stls(port: int = 110) -> str:
    import poplib
    c = poplib.POP3("127.0.0.1", port, timeout=20)
    capa = sorted(c.capa())
    c.stls()
    c.user("testuser")
    c.pass_("testpass")
    c.quit()
    return f"pop3 stls ok; capa={capa[:6]}"


def pop3_plain(port: int = 110) -> str:
    import poplib
    c = poplib.POP3("127.0.0.1", port, timeout=20)
    capa = sorted(c.capa())
    c.user("testuser")
    c.pass_("testpass")
    c.quit()
    return f"pop3 cleartext; capa={capa[:6]}"


def imaps_implicit(port: int = 993) -> str:
    """Implicit TLS: encrypted from the first byte, no capability exchange in clear."""
    import imaplib
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    c = imaplib.IMAP4_SSL("127.0.0.1", port, ssl_context=ctx)
    c.login("testuser", "testpass")
    c.logout()
    return "imaps implicit TLS login ok"


def pop3s_implicit(port: int = 995) -> str:
    import poplib
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    c = poplib.POP3_SSL("127.0.0.1", port, context=ctx, timeout=20)
    c.user("testuser")
    c.pass_("testpass")
    c.quit()
    return "pop3s implicit TLS login ok"


# ---------------------------------------------------------------- scenarios
def run(results: List[dict], vendor: str, protocol: str, tls_mode: str,
        scenario: str, port: int, driver: Callable, expect: str) -> None:
    name = f"{vendor}_{protocol}_{scenario}"
    entry = {"vendor": vendor, "protocol": protocol, "tls_mode": tls_mode,
             "scenario": scenario, "pcap": f"{name}.pcap", "expected": expect}
    try:
        with Capture(name, port):
            entry["client_result"] = driver(port)
        entry["status"] = "captured"
    except Exception as exc:                      # a refusal is itself a result
        entry["status"] = "client_error"
        entry["client_result"] = f"{type(exc).__name__}: {exc}"
    results.append(entry)
    print(f"[{entry['status']:12s}] {name}: {entry.get('client_result','')[:90]}",
          flush=True)


def main() -> None:
    os.makedirs(OUT, exist_ok=True)
    make_certs()
    results: List[dict] = []

    start_postfix(tls="may")
    run(results, "postfix", "smtp", "starttls", "starttls_upgrade", 25,
        smtp_starttls, "STARTTLS advertised and upgrade completes")
    run(results, "postfix", "smtp", "starttls", "client_declines", 25,
        smtp_declines, "STARTTLS advertised, client never upgrades")
    run(results, "postfix", "smtp", "cleartext", "plaintext_session", 25,
        smtp_plain, "cleartext dialogue, advertisement present")

    start_postfix(tls="none")
    run(results, "postfix", "smtp", "none", "no_starttls_offered", 25,
        smtp_plain, "no STARTTLS advertised; absence must stay AMBIGUOUS")

    start_dovecot()
    run(results, "dovecot", "imap", "starttls", "starttls_upgrade", 143,
        imap_starttls, "STARTTLS advertised and upgrade completes")
    run(results, "dovecot", "imap", "cleartext", "plaintext_login", 143,
        imap_plain, "cleartext LOGIN")
    run(results, "dovecot", "pop3", "starttls", "stls_upgrade", 110,
        pop3_stls, "STLS advertised and upgrade completes")
    run(results, "dovecot", "pop3", "cleartext", "plaintext_login", 110,
        pop3_plain, "cleartext USER/PASS")

    run(results, "dovecot", "imap", "implicit", "imaps_implicit_tls", 993,
        imaps_implicit, "implicit TLS; no cleartext capability exchange at all")
    run(results, "dovecot", "pop3", "implicit", "pop3s_implicit_tls", 995,
        pop3s_implicit, "implicit TLS; no cleartext capability exchange at all")

    with open(os.path.join(OUT, "scenarios.json"), "w") as fh:
        json.dump(results, fh, indent=1, sort_keys=True)
    print(f"\n{len(results)} scenarios, {sum(1 for r in results if r['status']=='captured')} captured")


if __name__ == "__main__":
    main()
