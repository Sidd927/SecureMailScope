"""
Phase-6 §10 dataset inventory for the EXISTING corpus (generator A = oq28/craft.py).

Runs the real pipeline (no shortcuts, no re-parsing) so the counts describe the data
the ML layer will actually see:  PCAP -> analyze_capture -> reconstruct_sessions.
"""
import json, os, sys, time
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from securemailscope.ingest import analyze_capture
from securemailscope.session import reconstruct_sessions

PC = os.path.join(os.path.dirname(__file__), "..", "oq28", "pcaps")

def main() -> None:
    gt = json.load(open(os.path.join(PC, "ground_truth.json")))
    total, per_capture = 0, {}
    proto, tlsmode, tlsver, appstate, complete = Counter(), Counter(), Counter(), Counter(), Counter()
    clients, servers = set(), set()
    t0 = time.time()
    for name in sorted(os.listdir(PC)):
        if not name.endswith(".pcap"):
            continue
        run, frames = analyze_capture(os.path.join(PC, name))
        sessions = reconstruct_sessions(frames, run.capture.capture_id)
        per_capture[name] = len(sessions)
        total += len(sessions)
        for s in sessions:
            proto[s.protocol] += 1
            tlsmode["implicit" if s.implicit_tls else "explicit"] += 1
            tlsver[str(s.tls_negotiated_version.value or s.tls_negotiated_version.state.value)] += 1
            appstate[s.app_state.value] += 1
            complete[s.completeness.value] += 1
            clients.add(s.client_ip); servers.add(s.server_ip)
    el = time.time() - t0
    print(f"GENERATOR A (oq28/craft.py)  pipeline time {el:.1f}s "
          f"({el/max(1,len(per_capture)):.2f}s/capture)")
    print(f"captures={len(per_capture)} sessions={total} "
          f"clients={len(clients)} servers={len(servers)}")
    print("per-capture:", json.dumps(per_capture))
    print("protocol:", dict(proto))
    print("tls_mode:", dict(tlsmode))
    print("tls_version:", dict(tlsver))
    print("app_state:", dict(appstate))
    print("completeness:", dict(complete))
    print("ground-truth cases:", len(gt))
    print("gt labels:", dict(Counter(v.get("truth", v.get("label", "?")) if isinstance(v, dict) else "?"
                                     for v in gt.values())))

if __name__ == "__main__":
    main()
