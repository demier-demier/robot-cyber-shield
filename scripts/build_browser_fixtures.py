#!/usr/bin/env python3
"""Generate signed synthetic public demo fixtures; discard private keys.

Browser verification uses a fixed logical mission clock, not the visitor's wall
clock. These publicly visible fixture grants are never robot credentials.
"""
from __future__ import annotations
import argparse
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
NOW = 1_000_000


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--refresh", action="store_true")
    args = parser.parse_args()
    destination = ROOT / "web/wasm/demo-fixtures.json"
    if destination.exists() and not args.refresh:
        print("Keeping existing signed public fixtures; use --refresh for new ephemeral keys.")
        return
    binary = ROOT / "target/debug" / ("robot-cyber-shield.exe" if os.name == "nt" else "robot-cyber-shield")
    with tempfile.TemporaryDirectory(prefix="robot-shield-fixtures-") as temporary:
        work = Path(temporary)
        def invoke(*args):
            subprocess.run([str(binary), *map(str, args)], check=True, stdout=subprocess.DEVNULL)
        for role in ("authority", "planner", "sensor", "other"):
            invoke("keygen", "--private-key", work / f"{role}.private", "--public-key", work / f"{role}.public")
        policy = dict(schema="robot-policy/v1", robot_id="demo-rover", session_id="demo-mission",
                      command_principal="planner", telemetry_principal="sensor",
                      max_linear_mps=0.5, max_angular_rps=0.8, max_request_age_ms=2000,
                      max_grant_ttl_ms=3600000, min_command_interval_ms=10,
                      command_lease_ms=250, position_grid_m=5.0)
        counter = 0
        def signed(role="planner", operation="command", expired=False, **changes):
            nonlocal counter
            counter += 1
            claims = dict(schema="robot-grant/v1", grant_id="demo-"+role,
                          robot_id="demo-rover", session_id="demo-mission",
                          principal="sensor" if operation == "telemetry" else "planner",
                          holder_public_key=(work/f"{role}.public").read_text().strip(),
                          not_before_ms=NOW-10000, expires_at_ms=NOW-1 if expired else NOW+60000,
                          capabilities=[operation], max_linear_mps=0.5, max_angular_rps=0.8)
            request = dict(robot_id="demo-rover", session_id="demo-mission", principal=claims["principal"],
                           sequence=1, issued_at_ms=NOW-2 if expired else NOW)
            if operation == "command":
                request.update(linear_mps=0.25, angular_rps=0.0)
            else:
                request.update(status="moving", battery_percent=80, position_x_m=12.12, position_y_m=-1.25,
                               raw_camera="SYNTHETIC_DEMO_FRAME", raw_audio="SYNTHETIC_DEMO_AUDIO",
                               operator_identity="SYNTHETIC_DEMO_OPERATOR")
            request.update(changes)
            files = {name:work/f"{counter}-{name}.json" for name in ("claims","grant","request","envelope")}
            files["claims"].write_text(json.dumps(claims))
            files["request"].write_text(json.dumps(dict(op=operation,request=request)))
            invoke("issue","--private-key",work/"authority.private","--claims",files["claims"],"--output",files["grant"])
            invoke("sign-request","--private-key",work/f"{role}.private","--grant",files["grant"],"--request",files["request"],"--output",files["envelope"])
            return json.loads(files["envelope"].read_text())
        valid = signed()
        tamper = copy.deepcopy(valid)
        tamper["request"]["linear_mps"] = 0.45
        wrong = copy.deepcopy(valid)
        wrong["request_signature"] = signed("other")["request_signature"]
        def case(envelopes, reasons, revoke_before=None, step_ms=20):
            return dict(steps=[dict(envelope=e,now_ms=NOW+i*step_ms) for i,e in enumerate(envelopes)],
                        expected_reasons=reasons, revoke_before=revoke_before)
        authorized_stream = [valid] + [signed(sequence=i+1, issued_at_ms=NOW+i*100) for i in range(1, 28)]
        fixture = dict(schema="robot-shield-browser-fixtures/v1", logical_now_ms=NOW,
                       clock="recorded_mission_clock", state_persistence="memory",
                       authority_public_key=(work/"authority.public").read_text().strip(), policy=policy,
                       provenance="Original synthetic signed fixtures. Private signing keys discarded after generation. Never use these grants with a real robot.",
                       scenarios={
                           "authorized":case(authorized_stream,["authorized"]*28,step_ms=100),
                           "tamper":case([tamper],["invalid_request_signature"]),
                           "wrong_holder":case([wrong],["invalid_request_signature"]),
                           "overspeed":case([signed(linear_mps=2.0)],["motion_limit"]),
                           "replay":case([valid,valid],["authorized","replay"]),
                           "telemetry":case([signed("sensor","telemetry")],["authorized"]),
                           "expired":case([signed(expired=True)],["grant_time"]),
                           "revoked":case([valid],["revoked"],"demo-planner"),
                       })
        destination.parent.mkdir(parents=True,exist_ok=True)
        destination.write_text(json.dumps(fixture,indent=2)+"\n")
        print("Wrote public fixture envelopes and public key; ephemeral private keys discarded.")

if __name__ == "__main__":
    main()
