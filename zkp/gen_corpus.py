#!/usr/bin/env python3
"""zkp/gen_corpus.py — K distinct REAL Groth16 proofs for Experiment 1.

Each proof is a different doctor (fresh DID, fresh credential issued by the CI)
authorizing against the same policy, with its own scoped-state digest rho_i —
i.e. K independent requests of one verification window (eq. 23).

Usage (from the repo root, with env.sh sourced):
    $FLEX_PY zkp/gen_corpus.py [K]        (default K = 32)
Needs zkp/build from zkp/build_zkp.sh. Writes build/corpus/{proof,public}_i.json.
"""

import os
import shutil
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from flex_diam import zkp  # noqa: E402
from flex_diam.hashing import field_of_digest, field_of_str  # noqa: E402
from flex_diam.protocol import Req, new_entity, scoped_digest  # noqa: E402

POLICY = ["CARDIOLOGY", "DOCTOR"]


def main() -> int:
    k = int(sys.argv[1]) if len(sys.argv) > 1 else 32
    corpus = os.path.join(zkp.BUILD, "corpus")
    shutil.rmtree(corpus, ignore_errors=True)
    os.makedirs(corpus)
    pid = zkp.policy_pid(POLICY)
    h_s, h_d = new_entity("hospital"), new_entity("hospital")
    for i in range(k):
        d = new_entity("doctor")
        vc = zkp.issue_vc(POLICY, field_of_str(d.did), int(time.time()) + 365 * 86400)
        req = Req(d.did, h_s.did, h_d.did, "cid:corpus", pid)
        rho = scoped_digest(req, (0, 0, 0, 0))
        pf, pub, _ = zkp.prove(vc, pid, field_of_digest(bytes.fromhex(rho)), POLICY, corpus, tag=f"t{i}")
        os.replace(pf, os.path.join(corpus, f"proof_{i}.json"))
        os.replace(pub, os.path.join(corpus, f"public_{i}.json"))
        os.remove(os.path.join(corpus, f"t{i}_input.json"))
        print(f"proof_{i} done")
    print(f"corpus: {k} proofs in {corpus}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
