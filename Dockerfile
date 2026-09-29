# SecureMailScope backend — Render (or any Docker host).
#
# TShark is an OS-level package. Render's native Python runtime has no apt access
# during build, so this is a Docker deployment specifically to install it (see
# docs/deployment/DEPLOYMENT-ARCHITECTURE.md). The tshark invocation in
# src/securemailscope/dissect/tshark.py is read-only file parsing only
# (`tshark -r <file> -T ek`) -- no live capture, so no extra capabilities/setcap
# are needed here, just the package itself.
#
# Base image note: this project's golden cases were established against TShark
# 4.6.8. Debian's own default apt repo (on both bookworm and trixie, verified
# during deployment audit) ships the legacy 4.4.x branch, which was empirically
# found to change analysis output for this project's own golden captures --
# same input PCAP, same application code, different TShark version, different
# score (44.0/CRITICAL became 72.0/WEAK). Ubuntu 24.04 + the official
# "Wireshark Developers" PPA (ppa:wireshark-dev/stable, back-ported release
# builds -- see https://launchpad.net/~wireshark-dev/+archive/ubuntu/stable)
# was verified during that same audit to provide 4.6.6, which reproduces the
# golden cases exactly. Do not switch this base image without re-verifying the
# golden cases against whatever TShark version the new image provides.

FROM ubuntu:24.04

# tshark's postinst asks an interactive question about non-superuser capture; this
# app never captures live traffic, so the default (non-interactive) answer is fine.
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        software-properties-common gnupg curl ca-certificates \
        python3 python3-venv python3-pip \
    && add-apt-repository -y ppa:wireshark-dev/stable \
    && apt-get update \
    && apt-get install -y --no-install-recommends tshark \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Ubuntu 24.04's system Python is externally-managed (PEP 668); a venv is the clean
# way to pip-install into it without --break-system-packages.
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies first so the pip layer only rebuilds when they change,
# not on every source edit.
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir ".[backend,reporting-pdf]"

# The dashboard's static assets ship as package data (see pyproject.toml
# [tool.setuptools.package-data]); the pip install above already picked them up from
# src/securemailscope/dashboard/static via the editable-less install above.

ENV SMS_DATA_DIR=/data
RUN mkdir -p /data

EXPOSE 8000

# --host 0.0.0.0: Docker/Render need the service reachable from outside the
# container, unlike the 127.0.0.1 local-dev default (see __main__.py's docstring on
# why that default exists -- this prototype has no authentication, ADR-0011).
CMD ["python3", "-m", "securemailscope.backend", "--host", "0.0.0.0", "--data-dir", "/data"]
