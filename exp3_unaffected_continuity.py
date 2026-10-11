#!/usr/bin/env python3
"""exp3_unaffected_continuity.py — Experiment 3 / Fig. 4: Unaffected-User
Continuity After Revocation.

Paper: "The number of revoked users is varied from 0 to 2,000 while a fixed
non-revoked doctor D_j accesses an unchanged EHR. After each revocation
workload, D_j executes authorization, cross-domain delegation, and retrieval
using the same CP-ABE key and stored ciphertext. End-to-end access latency is
measured from authorization request submission to successful release of the
transformed key material."

Produces  exp3_unaffected_continuity.csv
    revoked_users,Ref [20],Ref [24],Ref [28],FLEX-DIAM        (cells = ms)
and       exp3_unaffected_continuity_detail.csv  (per-stage breakdown)

What one cell is:

  FLEX-DIAM  REAL execution on the live network. The ledger really holds N
             revoked doctors (cumulative RevokeUsers transactions), then D_j
             runs FlexDiam.access(): Phase 3 Steps 1-6, Phase 4 Steps 1-6 and
             Phase 5 Step 1, with a real Groth16 proof, the real batch verifier,
             real ABPRE and every blockchain read / write of those steps. D_j's
             CP-ABE key, credential and the stored ciphertext are created once
             and never touched again. After the clock stops, D_j recovers K_AES
             and decrypts; the plaintext is compared with the original.
  Ref [20]   D_j's evidence update for N revocations + one cross-domain
             authentication (Sign + Verify) + 1 real on-chain read.
  Ref [24]   D_j's authentication-function updates for the N revocations (one
             per gateway update round, SRAA_BATCH) + one cross-domain access
             authentication (no blockchain in SRAA).
  Ref [28]   no per-user update + one cross-domain authentication + 1 real
             on-chain read.

At every N the driver also records two correctness facts (CHECKS=1):
  continuity   a token issued to D_j BEFORE the new revocations still passes
               delegation and release afterwards (rho_j unchanged);
  enforcement  a doctor revoked in this workload fails Valid_rev (eq. 18).

Env: TRIALS (accesses per N inside this run, default 3), PILOT, OUT, CHECKS.
Run via run_exp3.sh.
"""

import csv
import os
import statistics
import sys

from baselines import li, wang, zeng
from flex_diam import cost_model
from flex_diam.chain import FabricLedger, require_real
from flex_diam.protocol import FlexDiam, Rejected, Req, default_work_dir, new_entity

N_VALUES = [0, 100, 250, 500, 750, 1000, 1250, 1500, 1750, 2000]
BASELINES = {"Ref [20]": zeng, "Ref [24]": li, "Ref [28]": wang}
POLICY = ["CARDIOLOGY", "DOCTOR"]          # access policy A of the stored EHR
NUM_HOSPITALS = 10                         # consortium size stated in Section V
REGISTER_CHUNK = 600
PAYLOAD = b"synthetic EHR record: patient vitals + clinical note " * 8

STAGES = [
    "p3_s1_resolve_state", "p3_s2_validate", "p3_s3_zk_prove", "p3_s4_batch_verify",
    "p3_s5_token_issue", "p3_s6_batch_anchor", "p4_s2_state_validation", "p4_s3_dac_issue",
    "p4_s4_rekeygen", "p4_s5_reenc", "p4_s6_delegation_audit", "p5_s1_release_validation",
]


def revoke_more(fd: FlexDiam, count: int) -> list:
    """Register `count` new doctors and revoke them (eq. 50). Untimed."""
    doctors = [new_entity("doctor") for _ in range(count)]
    for i in range(0, count, REGISTER_CHUNK):
        chunk = doctors[i:i + REGISTER_CHUNK]
        fd.ledger.register_dids([(d.did, d.pk_hex) for d in chunk])
    dids = [d.did for d in doctors]
    fd.revoke_users(dids)
    return dids


def main() -> int:
    pilot = bool(os.environ.get("PILOT"))
    trials = int(os.environ.get("TRIALS", "2" if pilot else "3"))
    n_values = [0, 100] if pilot else N_VALUES
    checks = os.environ.get("CHECKS", "1") != "0"
    out_path = os.environ.get("OUT", "exp3_unaffected_continuity_PILOT.csv" if pilot else "exp3_unaffected_continuity.csv")

    ledger = FabricLedger()
    require_real(ledger)
    fd = FlexDiam(ledger, default_work_dir())

    print(f"=== Experiment 3 (unaffected-user continuity): TRIALS={trials}, pilot={pilot} ===\n")

    print("[1/3] Setup (untimed): consortium, D_j, one encrypted EHR...")
    hospitals = fd.register_many("hospital", NUM_HOSPITALS)
    h_s, h_d = hospitals[0], hospitals[1]
    patient = fd.register("patient")
    d_j = fd.enroll_doctor(h_d, POLICY)                    # DID, VC, SK_D — issued once
    rec = fd.encrypt_ehr(patient, h_s, PAYLOAD, POLICY)    # CT, Meta, Com — stored once
    req = Req(d_j.did, h_s.did, h_d.did, rec.cid, rec.pid)
    print(f"  D_j = {d_j.did}\n  cid = {rec.cid}\n  pid = {rec.pid[:16]}...")

    warm = fd.access(d_j, rec, h_s.did, h_d.did)           # warm caches; not recorded
    if warm.plaintext != PAYLOAD:
        sys.exit("warm-up access did not recover the EHR — aborting")
    for mod in BASELINES.values():
        mod.access_auth_ns()
        mod.user_maintenance_ns(2)
    print(f"  warm-up access released in {warm.released_ms:.0f} ms\n")

    print("[2/3] Sweeping the revocation workload...")
    rows, detail = [], []
    revoked = 0
    for n in n_values:
        pre_tok = None
        if checks and n > revoked:
            # token issued to D_j BEFORE this workload is revoked
            pre_tok = fd.authorize_batch([(d_j, req, POLICY)])[0]
            if isinstance(pre_tok, Rejected):
                sys.exit(f"pre-revocation authorization failed: {pre_tok}")
        new_dids = revoke_more(fd, n - revoked) if n > revoked else []
        revoked = n

        continuity, enforcement = "", ""
        if checks and new_dids:
            try:
                fd.delegate_and_release(req, pre_tok)
                continuity = 1
            except Rejected as e:
                continuity = 0
                print(f"  !! continuity check FAILED at N={n}: {e}")
            st, _, _ = fd.authz_resolve(Req(new_dids[0], h_s.did, h_d.did, rec.cid, rec.pid))
            enforcement = 0 if fd.valid_rev(Req(new_dids[0], h_s.did, h_d.did, rec.cid, rec.pid), st) else 1

        # --- FLEX-DIAM: real end-to-end accesses by the unaffected doctor ---
        traces = []
        for _ in range(trials):
            tr = fd.access(d_j, rec, h_s.did, h_d.did)
            if tr.plaintext != PAYLOAD:
                sys.exit(f"access at N={n} did not recover the EHR — aborting")
            traces.append(tr)
        flex = [t.released_ms for t in traces]

        row = {"revoked_users": n, "FLEX-DIAM": statistics.mean(flex)}
        drow = {"revoked_users": n, "FLEX-DIAM stdev": statistics.pstdev(flex)}
        for s in STAGES:
            drow[f"FLEX {s}"] = statistics.mean(t.stages[s] for t in traces)
        drow["FLEX chain_read_total"] = statistics.mean(t.chain_read_ms for t in traces)
        drow["FLEX chain_write_total"] = statistics.mean(t.chain_write_ms for t in traces)
        drow["FLEX post_release_recover_decrypt"] = statistics.mean(
            t.post_release["p5_s2_s3_recover_decrypt"] for t in traces)
        drow["FLEX post_release_access_audit"] = statistics.mean(
            t.post_release["p5_s4_access_audit"] for t in traces)

        # --- baselines: D_j's own maintenance + one authentication (+ real read) ---
        for scheme, mod in BASELINES.items():
            maint, auth, chain = [], [], []
            for _ in range(trials):
                maint.append(mod.user_maintenance_ns(n) / 1e6)
                auth.append(mod.access_auth_ns() / 1e6)
                chain.append(sum(ledger.get_anchor("exp3")[1]
                                 for _ in range(cost_model.exp3_chain_reads(scheme))))
            row[scheme] = statistics.mean(maint) + statistics.mean(auth) + statistics.mean(chain)
            drow[f"{scheme} maintenance"] = statistics.mean(maint)
            drow[f"{scheme} auth"] = statistics.mean(auth)
            drow[f"{scheme} chain_read"] = statistics.mean(chain)
        drow["continuity_ok"] = continuity
        drow["revoked_rejected"] = enforcement
        rows.append(row)
        detail.append(drow)
        print(f"  N={n:<5} [20]={row['Ref [20]']:8.1f}  [24]={row['Ref [24]']:8.1f}  "
              f"[28]={row['Ref [28]']:8.1f}  FLEX={row['FLEX-DIAM']:8.1f} ms "
              f"(stdev {drow['FLEX-DIAM stdev']:.0f}; continuity={continuity}, "
              f"revoked rejected={enforcement})")

    print("\n[3/3] Writing CSVs...")
    with open(out_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["revoked_users"] + cost_model.SCHEMES)
        for row in rows:
            w.writerow([row["revoked_users"]] + [f"{row[s]:.2f}" for s in cost_model.SCHEMES])
    detail_path = out_path.replace(".csv", "_detail.csv")
    cols = [c for c in detail[0] if c != "revoked_users"]
    with open(detail_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["revoked_users"] + cols)
        for drow in detail:
            w.writerow([drow["revoked_users"]]
                       + [("" if drow[c] == "" else f"{drow[c]:.2f}") for c in cols])
    print(f"Wrote {out_path} and {detail_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
