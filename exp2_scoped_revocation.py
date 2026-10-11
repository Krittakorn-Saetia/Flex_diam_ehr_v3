#!/usr/bin/env python3
"""exp2_scoped_revocation.py — Experiment 2 / Fig. 3: Scoped User Revocation Overhead.

Paper: "evaluates the scalability of scoped user revocation as the number of
revoked users increases from 100 to 2,000 ... End-to-end latency includes the
revocation-state update and its blockchain confirmation. For each revoked doctor
D_i, FLEX-DIAM updates the revocation list and increments only the corresponding
user version (eq. 50) ... Maintenance incurred by unaffected users is evaluated
separately in Experiment 3."

Produces  exp2_scoped_revocation.csv
    revoked_users,Ref [20],Ref [24],Ref [28],FLEX-DIAM        (cells = ms)
and       exp2_scoped_revocation_detail.csv  (crypto / chain split per scheme)

What one cell is:

  FLEX-DIAM  REAL execution. N freshly registered doctors are revoked on the
             live Fabric network: every doctor gets RL <- RL U {DID}, v_D += 1
             (eq. 50). Timed from submission to commit confirmation.
             REVOKE_MODE=batch  (default) one RevokeUsers transaction for the
                                workload — one blockchain confirmation;
             REVOKE_MODE=per_tx N RevokeUser transactions submitted
                                concurrently, timed until all are committed.
  Ref [20]   N accumulator updates by the domain manager (fully executed in
             Charm) + 1 on-chain publication.
  Ref [24]   the gateway's update rounds for the N revoked twins (Phi, the
             expansion of Psi, f* = u*f), fully executed on a real polynomial.
             One round per revoked twin by default (SRAA_BATCH). SRAA has no
             blockchain, so no confirmation is added.
  Ref [28]   N chameleon-hash forges (fully executed) + 1 primary-chain
             broadcast.
  Baseline on-chain steps = count (cost_model.exp2_chain_writes) * the write
  unit calibrated live on the same network. Per-user maintenance of UNAFFECTED
  users (witness / authentication-function updates) is NOT charged here.

Env: TRIALS (repetitions per N inside this run, default 3), PILOT, OUT,
     REVOKE_MODE (batch|per_tx), CONCURRENCY (per_tx only, default 32),
     REGISTER_WORKLOAD (default 1: workload doctors are registered first, untimed).
Run via run_exp2.sh.
"""

import csv
import os
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor

from baselines import li, wang, zeng
from flex_diam import chain_meter, cost_model
from flex_diam.chain import FabricLedger, require_real
from flex_diam.protocol import new_entity

N_VALUES = [100, 250, 500, 750, 1000, 1250, 1500, 1750, 2000]
BASELINES = {"Ref [20]": zeng, "Ref [24]": li, "Ref [28]": wang}
REGISTER_CHUNK = 600  # (DID, pk) pairs per setup transaction (CLI argument size)


def make_workload(ledger, n: int, register: bool) -> list:
    """N fresh doctor identities (eq. 2-3), registered on chain. Untimed."""
    doctors = [new_entity("doctor") for _ in range(n)]
    if register:
        for i in range(0, n, REGISTER_CHUNK):
            ledger.register_dids([(d.did, d.pk_hex) for d in doctors[i:i + REGISTER_CHUNK]])
    return [d.did for d in doctors]


def flex_revoke_ms(ledger, dids: list, mode: str, concurrency: int) -> float:
    """Real scoped revocation of the workload, submission -> commit."""
    if mode == "batch":
        _, ms = ledger.revoke_users(dids)
        return ms
    t0 = time.perf_counter_ns()
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        list(pool.map(ledger.revoke_user, dids))
    return (time.perf_counter_ns() - t0) / 1e6


def main() -> int:
    pilot = bool(os.environ.get("PILOT"))
    trials = int(os.environ.get("TRIALS", "2" if pilot else "3"))
    n_values = [100, 250] if pilot else N_VALUES
    mode = os.environ.get("REVOKE_MODE", "batch")
    concurrency = int(os.environ.get("CONCURRENCY", "32"))
    register = os.environ.get("REGISTER_WORKLOAD", "1") != "0"
    out_path = os.environ.get("OUT", "exp2_scoped_revocation_PILOT.csv" if pilot else "exp2_scoped_revocation.csv")
    if mode not in ("batch", "per_tx"):
        sys.exit("REVOKE_MODE must be 'batch' or 'per_tx'")

    ledger = FabricLedger()
    require_real(ledger)

    print(f"=== Experiment 2 (scoped user revocation overhead): TRIALS={trials}, "
          f"REVOKE_MODE={mode}, pilot={pilot} ===\n")

    print("[1/3] Calibrating chain write unit (live Fabric)...")
    cal = chain_meter.calibrate(ledger, samples=5 if pilot else 20)
    t_write = cal["write_ms"]
    print(f"  T_BC write = {t_write:7.1f} ms (stdev {cal['write_stdev']:.1f})\n")

    for mod in BASELINES.values():
        mod.authority_revoke_ns(2)  # warm (group / parameter setup)

    print("[2/3] Sweeping N (every operation executed for real)...")
    rows, detail = [], []
    for n in n_values:
        row = {"revoked_users": n}
        drow = {"revoked_users": n, "t_bc_write": t_write}
        for scheme, mod in BASELINES.items():
            crypto = statistics.mean(mod.authority_revoke_ns(n) / 1e6 for _ in range(trials))
            chain = cost_model.exp2_chain_writes(scheme) * t_write
            row[scheme] = crypto + chain
            drow[f"{scheme} crypto"] = crypto
            drow[f"{scheme} chain"] = chain
        flex_ts = []
        for _ in range(trials):
            dids = make_workload(ledger, n, register)
            flex_ts.append(flex_revoke_ms(ledger, dids, mode, concurrency))
        row["FLEX-DIAM"] = statistics.mean(flex_ts)
        drow["FLEX-DIAM stdev"] = statistics.pstdev(flex_ts)
        rows.append(row)
        detail.append(drow)
        print(f"  N={n:<5} [20]={row['Ref [20]']:9.1f}  [24]={row['Ref [24]']:9.1f}  "
              f"[28]={row['Ref [28]']:9.1f}  FLEX={row['FLEX-DIAM']:9.1f} ms "
              f"(FLEX stdev {drow['FLEX-DIAM stdev']:.0f})")

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
            w.writerow([drow["revoked_users"]] + [f"{drow[c]:.2f}" for c in cols])
    print(f"Wrote {out_path} and {detail_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
