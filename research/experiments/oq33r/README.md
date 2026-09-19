# OQ-33r — Real-vendor mail traffic

Captures of **real Postfix and Dovecot** traffic, used to validate SecureMailScope
against software we did not write. Full analysis: `docs/research/23-oq33r-real-world-validation.md`.

| File | Purpose |
|---|---|
| `Dockerfile` | Alpine + Postfix + Dovecot + tcpdump |
| `Dockerfile.exim` | Exim, built but not yet driven (separate image: both MTAs claim `/usr/sbin/sendmail`) |
| `capture.py` | runs inside the container: starts a server, records loopback, drives it with Python clients |
| `validate.py` | runs the pipeline over each capture and cross-checks against an independent tshark raw-byte read |
| `out/` | 10 captures + `scenarios.json` (64 KB, committed) |
| `results/validation-matrix.json` | the validation matrix |

## Safety

Disposable container, one throwaway local account, synthetic message text, a self-signed
certificate generated per run (`test.pem` / `test.key` are **git-ignored**), no real mail
and no personal data.

## Reproducing

```bash
export DOCKER_HOST="unix://$HOME/.colima/default/docker.sock"   # or your docker socket
docker build -t sms-oq33r -f research/experiments/oq33r/Dockerfile research/experiments/oq33r
docker run --name sms-oq33r-run --rm -d --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -v "$PWD/research/experiments/oq33r:/corpus" sms-oq33r sleep 3600
docker exec sms-oq33r-run python3 /corpus/capture.py
docker rm -f sms-oq33r-run
PYTHONPATH=src python3 research/experiments/oq33r/validate.py
```

The pcaps are **not** byte-reproducible: packet timings and TLS randoms differ per run.
The crafted corpora (`oq46_47/`, `oq36/`) are reproducible; this one deliberately is not,
because it records real software behaving in real time.

## Two implementation notes worth keeping

* **Do not let a daemon inherit the capture script's stdout.** Dovecot and Postfix
  configured with `log_path = /dev/stdout` keep the pipe open, so `subprocess.run(...,
  capture_output=True)` waits for the daemon to exit rather than for the start command to
  return. This silently hung two runs before it was diagnosed; both now log to files, and
  `sh()` carries a hard timeout.
* **Do not restart Dovecot mid-run to change its configuration.** Reconfiguring a live
  master reliably left the old listeners in place, silently giving a later scenario the
  earlier configuration. A corpus that lies about what the server offered is worse than
  one scenario fewer.
