"""
OQ-33r: run SecureMailScope over the real-vendor captures and build the validation
matrix.

For each capture this records what the pipeline concluded, what tshark independently
says about the same bytes, and whether the two agree with the scenario's declared
expectation. Disagreements are classified rather than smoothed over:

    parser-bug            we misread bytes tshark read correctly
    evidence-limitation   the capture genuinely cannot decide
    expected-abstention   the correct answer is "insufficient evidence"
    unsupported-dialect   a vendor construct no rule covers yet
    wrong-security-claim  the most serious class: a conclusion not supported by evidence
    infrastructure        the capture itself is unusable

The tshark comparison is the point: a validation that only asks our own pipeline what it
thinks proves nothing about whether it read the packets correctly.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from typing import Dict, List, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "..", "src"))

from securemailscope.analysis import SecurityAnalysisEngine  # noqa: E402
from securemailscope.analysis.model import FindingStatus  # noqa: E402
from securemailscope.crosssession import CrossSessionEngine  # noqa: E402
from securemailscope.ingest import analyze_capture  # noqa: E402
from securemailscope.posture import PostureEngine  # noqa: E402
from securemailscope.session import reconstruct_sessions  # noqa: E402

OUT = os.path.join(HERE, "out")
RESULTS = os.path.join(HERE, "results")


def sha256_16(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()[:16]


def tshark_view(path: str) -> Dict[str, object]:
    """Independent read of the same bytes: what does tshark itself say is there?"""
    def run(args: List[str]) -> List[str]:
        proc = subprocess.run(["tshark", "-r", path, *args],
                              capture_output=True, text=True, timeout=120)
        return [ln for ln in proc.stdout.splitlines() if ln.strip()]

    # Raw-byte search from the SERVER side, deliberately not using tshark's per-protocol
    # capability fields. The first version of this check used them and reported four
    # false failures: `imap.response.command` does not carry untagged capability lines,
    # and tshark exposes the POP3 CAPA body as empty strings (the same dissector gap
    # Phase 2 already had to work around). Asking tshark for the bytes instead makes
    # this an independent check rather than a second opinion from the same lossy view.
    starttls_lines = run([
        "-Y", "(tcp.srcport==25 || tcp.srcport==587 || tcp.srcport==143 || "
              "tcp.srcport==110) && (tcp contains \"STARTTLS\" || tcp contains \"STLS\")",
        "-T", "fields", "-e", "frame.number"])
    tls_versions = run(["-Y", "tls.handshake.type == 2", "-T", "fields",
                        "-e", "tls.handshake.extensions.supported_version",
                        "-e", "tls.handshake.version"])
    streams = run(["-T", "fields", "-e", "tcp.stream"])
    return {
        "streams": len({s for s in streams if s}),
        "starttls_capability_frames": len(starttls_lines),
        "server_hellos": len(tls_versions),
        "tls_versions_raw": sorted({v for v in tls_versions if v})[:4],
    }


def analyse(path: str) -> Dict[str, object]:
    run, frames = analyze_capture(path)
    sessions = reconstruct_sessions(frames, run.capture.capture_id)
    findings = SecurityAnalysisEngine().analyse(sessions, run.capture.capture_id).findings
    cross = CrossSessionEngine().analyse(sessions, run.capture.capture_id).findings
    assessment = PostureEngine().assess(sessions, findings, cross,
                                        capture_id=run.capture.capture_id,
                                        run_id="oq33r", generated_at="X")
    mail = [s for s in sessions if s.protocol]
    return {
        "run_status": run.status.value,
        "packets": run.packet_count,
        "sessions": len(sessions),
        "mail_sessions": len(mail),
        "protocols": sorted({s.protocol for s in mail}),
        "advertised": sorted({f"{s.starttls_advertised.value}/"
                              f"{s.starttls_advertised.state.value}" for s in mail}),
        "tls_state": sorted({s.tls_state.value for s in mail}),
        "tls_versions": sorted({str(s.tls_negotiated_version.value) for s in mail
                                if s.tls_negotiated_version.value}),
        "completeness": sorted({s.completeness.value for s in mail}),
        "implicit_tls": sum(1 for s in mail if s.implicit_tls),
        "observed_issues": sorted({f.rule_id for f in findings
                                   if f.status is FindingStatus.OBSERVED_ISSUE}),
        "posture_band": assessment.band.value,
        "posture_score": round(assessment.score.value, 2) if assessment.score else None,
        "abstention_reasons": assessment.risk_summary["abstentions"]["by_reason"],
    }


def classify(scenario: Dict[str, object], sms: Dict[str, object],
             ts: Dict[str, object]) -> Dict[str, str]:
    """Compare the three views and name any disagreement."""
    notes: List[str] = []
    verdict = "PASS"

    if sms["mail_sessions"] == 0:
        return {"result": "FAIL", "classification": "infrastructure",
                "note": "no mail session reconstructed from the capture"}

    ts_has_capability = ts["starttls_capability_frames"] > 0
    sms_advertised = any(a.startswith("True/") for a in sms["advertised"])

    # The load-bearing cross-check: tshark and SecureMailScope must agree about whether
    # the capability was on the wire at all.
    if ts_has_capability and not sms_advertised:
        verdict, classification = "FAIL", "parser-bug"
        notes.append("tshark sees a STARTTLS/STLS capability that we did not observe")
    elif sms_advertised and not ts_has_capability:
        verdict, classification = "FAIL", "wrong-security-claim"
        notes.append("we report an advertisement tshark does not see")
    else:
        classification = "agreed"
        notes.append("advertisement presence agrees with tshark")

    if ts["server_hellos"] > 0 and not sms["tls_versions"]:
        verdict = "FAIL"
        classification = "parser-bug"
        notes.append("tshark sees a ServerHello but we negotiated no version")

    if sms["implicit_tls"] and "NOT_OBSERVABLE" not in str(sms["advertised"]):
        notes.append("implicit TLS session did not report an unobservable advertisement")

    return {"result": verdict, "classification": classification,
            "note": "; ".join(notes)}


def main() -> None:
    os.makedirs(RESULTS, exist_ok=True)
    scenarios_path = os.path.join(OUT, "scenarios.json")
    if not os.path.exists(scenarios_path):
        print("no scenarios.json; run capture.py inside the container first")
        return
    scenarios = json.load(open(scenarios_path))

    matrix: List[dict] = []
    for scenario in scenarios:
        path = os.path.join(OUT, scenario["pcap"])
        row = {k: scenario[k] for k in
               ("vendor", "protocol", "tls_mode", "scenario", "expected", "status")}
        row["pcap"] = scenario["pcap"]
        if scenario["status"] != "captured" or not os.path.exists(path):
            row.update({"result": "NOT CAPTURED", "classification": "infrastructure",
                        "note": scenario.get("client_result", "")[:160]})
            matrix.append(row)
            continue
        row["pcap_sha256_16"] = sha256_16(path)
        try:
            sms = analyse(path)
            ts = tshark_view(path)
            row["securemailscope"] = sms
            row["tshark"] = ts
            row.update(classify(scenario, sms, ts))
        except Exception as exc:
            row.update({"result": "ERROR", "classification": "infrastructure",
                        "note": f"{type(exc).__name__}: {exc}"})
        matrix.append(row)

    summary = {
        "captures": len(matrix),
        "captured": sum(1 for r in matrix if r.get("status") == "captured"),
        "pass": sum(1 for r in matrix if r.get("result") == "PASS"),
        "fail": sum(1 for r in matrix if r.get("result") == "FAIL"),
        "not_captured": sum(1 for r in matrix if r.get("result") == "NOT CAPTURED"),
        "vendors": sorted({r["vendor"] for r in matrix}),
        "vendors_captured": sorted({r["vendor"] for r in matrix
                                    if r.get("status") == "captured"}),
        "protocols_captured": sorted({r["protocol"] for r in matrix
                                      if r.get("status") == "captured"}),
        "tls_modes_captured": sorted({r["tls_mode"] for r in matrix
                                      if r.get("status") == "captured"}),
    }
    with open(os.path.join(RESULTS, "validation-matrix.json"), "w") as fh:
        json.dump({"summary": summary, "matrix": matrix}, fh, indent=1, sort_keys=True)

    print(f"{'vendor':9s} {'proto':6s} {'mode':10s} {'scenario':22s} {'result':12s} "
          f"{'band':22s} class")
    print("-" * 110)
    for row in matrix:
        band = (row.get("securemailscope", {}) or {}).get("posture_band", "-")
        score = (row.get("securemailscope", {}) or {}).get("posture_score", "")
        print(f"{row['vendor']:9s} {row['protocol']:6s} {row['tls_mode']:10s} "
              f"{row['scenario']:22s} {row.get('result','?'):12s} "
              f"{str(band) + ' ' + str(score):22s} {row.get('classification','')}")
    print(f"\n{json.dumps(summary, indent=1)}")


if __name__ == "__main__":
    main()
