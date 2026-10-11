#!/usr/bin/env python3
"""smoke_protocol.py — functional check of the FLEX-DIAM protocol (no timing).

Exercises Phases 1-5 and the properties the paper claims for them:

   1. an authorized cross-domain access recovers the EHR
   2. continuity: revoking ANOTHER doctor leaves D_j's existing token valid
   3. a revoked doctor is rejected by Valid_rev (eq. 18)
   4. a revoked doctor's earlier token is stale at delegation (eq. 34)
   5. policy-scope revocation makes old tokens stale; fresh authorization works
   6. context binding: ReDec under a different ctx returns bottom (eq. 39)
   7. a doctor whose credential lacks a required attribute cannot prove (eq. 22)
   8. a credential cannot be used under another DID (DID(VC) = DID_D)
   9. batch verification isolates an invalid request by recursive partition
  10. domain-scope revocation rejects every doctor of that domain

Usage:
    $FLEX_PY smoke_protocol.py --offline     in-memory ledger (no Docker needed)
    $FLEX_PY smoke_protocol.py               live Fabric network (chaincode deployed)
Both need the ZKP build (zkp/build_zkp.sh) and the native verifier binary.
"""

import dataclasses
import json
import os
import sys

from flex_diam import zkp
from flex_diam.chain import FabricLedger, MemoryLedger
from flex_diam.hashing import H, field_of_digest
from flex_diam.protocol import FlexDiam, Rejected, Req, default_work_dir, scoped_digest

POLICY = ["CARDIOLOGY", "DOCTOR"]
PAYLOAD = b"EHR: blood pressure 120/80, heart rate 72"
_results = []


def check(name: str, ok: bool) -> None:
    _results.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}")


def rejected_at(fn, stage: str) -> bool:
    try:
        fn()
    except Rejected as e:
        return e.stage == stage
    return False


def main() -> int:
    offline = "--offline" in sys.argv
    ledger = MemoryLedger() if offline else FabricLedger()
    fd = FlexDiam(ledger, default_work_dir())
    print(f"FLEX-DIAM protocol smoke test ({'in-memory ledger' if offline else 'live Fabric'})\n")

    h_s, h_d = fd.register_many("hospital", 2)
    patient = fd.register("patient")
    d_j = fd.enroll_doctor(h_d, POLICY)                    # unaffected doctor
    d_x = fd.enroll_doctor(h_d, POLICY)                    # will be revoked
    d_n = fd.enroll_doctor(h_d, ["DOCTOR", "NEUROLOGY"])   # does not satisfy A
    rec = fd.encrypt_ehr(patient, h_s, PAYLOAD, POLICY)
    req_j = Req(d_j.did, h_s.did, h_d.did, rec.cid, rec.pid)
    req_x = Req(d_x.did, h_s.did, h_d.did, rec.cid, rec.pid)

    # 1
    tr = fd.access(d_j, rec, h_s.did, h_d.did)
    check("1  authorized access recovers the EHR", tr.plaintext == PAYLOAD)

    # tokens issued before any revocation
    tok_j, tok_x = fd.authorize_batch([(d_j, req_j, POLICY), (d_x, req_x, POLICY)])
    check("   batch of two valid requests -> two tokens",
          not isinstance(tok_j, Rejected) and not isinstance(tok_x, Rejected))
    rho_before = scoped_digest(req_j, fd.authz_resolve(req_j)[0].sigma)

    fd.revoke_user(d_x.did)                                # eq. 50 on D_x only

    # 2
    rho_after = scoped_digest(req_j, fd.authz_resolve(req_j)[0].sigma)
    ok2 = rho_before == rho_after
    try:
        rec2, bundle, rho_rel, _dac = fd.delegate_and_release(req_j, tok_j)
        ok2 = ok2 and fd.doctor_recover(d_j, req_j, rec2, bundle, rho_rel) == PAYLOAD
    except Rejected:
        ok2 = False
    check("2  continuity: D_j's pre-revocation token still authorizes release", ok2)

    # 3
    check("3  revoked doctor rejected by Valid_rev",
          rejected_at(lambda: fd.access(d_x, rec, h_s.did, h_d.did), "p3_s2"))
    # 4
    check("4  revoked doctor's earlier token is stale at delegation",
          rejected_at(lambda: fd.delegate_and_release(req_x, tok_x), "p4_s2"))

    # 6 — context binding on the transformed key material released in step 2
    ctx = bundle["ctx"]
    other = H(ctx, "another context")
    k_ok = fd.abpre.redec(fd.pk, d_j.sk_abe, bundle["ct_kp"], ctx)
    k_bad = fd.abpre.redec(fd.pk, d_j.sk_abe, bundle["ct_kp"], other)
    forged = dict(bundle["ct_kp"])
    forged["tau"] = H("FLEX-DIAM/abpre/tau", other, fd.abpre.group.serialize(forged["q"]))
    k_forged = fd.abpre.redec(fd.pk, d_j.sk_abe, forged, other)
    check("6  ReDec under a different ctx returns bottom (also with a re-forged tag)",
          k_ok is not None and k_bad is None and k_forged is None)
    check("   ReDec with a key that does not satisfy A returns bottom",
          fd.abpre.redec(fd.pk, d_n.sk_abe, bundle["ct_kp"], ctx) is None)

    # 7
    check("7  credential without a required attribute cannot produce a proof",
          rejected_at(lambda: fd.access(d_n, rec, h_s.did, h_d.did), "p3_s3"))

    # 8 — D_n presents D_j's credential under its own DID
    thief = dataclasses.replace(d_n, vc=d_j.vc)
    check("8  credential bound to another DID is rejected",
          rejected_at(lambda: fd.access(thief, rec, h_s.did, h_d.did), "p3_s4"))

    # 9 — three proofs, the middle one presented with a different rho
    st, rho, _ = fd.authz_resolve(req_j)
    items = []
    for i in range(3):
        pf, pub, _ = fd.zk_prove(d_j, req_j, rho, POLICY, tag=f"s{i}")
        items.append((pf, pub))
    with open(items[1][1]) as f:
        pubs = json.load(f)
    pubs[2] = str(field_of_digest(H("stale scoped state")))
    with open(items[1][1], "w") as f:
        json.dump(pubs, f)
    valid, _, _ = zkp.batch_verify("bid:smoke", items)
    check("9  recursive partition isolates the invalid request", valid == [True, False, True])

    # 5 — policy scope
    fd.revoke_policy(rec.pid)
    stale = rejected_at(lambda: fd.delegate_and_release(req_j, tok_j), "p4_s2")
    fresh = fd.access(d_j, rec, h_s.did, h_d.did).plaintext == PAYLOAD
    check("5  policy-scope revocation: old token stale, fresh authorization works", stale and fresh)

    # 10 — domain scope
    fd.revoke_domain(h_d.did)
    check("10 domain-scope revocation rejects doctors of that domain",
          rejected_at(lambda: fd.access(d_j, rec, h_s.did, h_d.did), "p3_s2"))

    print(f"\n{sum(_results)}/{len(_results)} checks passed")
    return 0 if all(_results) else 1


if __name__ == "__main__":
    sys.exit(main())
