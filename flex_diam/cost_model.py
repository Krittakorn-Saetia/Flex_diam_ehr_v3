"""flex_diam.cost_model — how many blockchain operations each BASELINE scheme is
charged in each experiment.

FLEX-DIAM is never modelled here: its chain operations are executed for real by
the drivers. The baselines are implemented as cost-dominant cryptographic
operations (see NOTES_cost_dominant_ops.md), so their on-chain steps are charged
as count * live-calibrated unit (flex_diam.chain_meter).
"""

SCHEMES = ["Ref [20]", "Ref [24]", "Ref [28]", "FLEX-DIAM"]


def exp1_chain_reads_per_auth(scheme: str) -> int:
    """Experiment 1 — on-chain READs the verifier pays per authorization request.

    Ref [20]: the edge server fetches the latest accumulator value of the peer
              domain from the blockchain before verifying.
    Ref [28]: the server queries the blacklist tree / registration record.
    Ref [24]: SRAA authenticates locally (no blockchain in the scheme).
    FLEX-DIAM: 0 here — unchanged from the Fig. 2 measurement carried over from
              V2 (see PAPER_FIDELITY.md, item on Phase 3 Step 1)."""
    return 1 if scheme in ("Ref [20]", "Ref [28]") else 0


def exp1_chain_writes_per_window(scheme: str) -> int:
    """Experiment 1 — on-chain WRITEs per verification window: FLEX-DIAM anchors
    one batch commitment per window (eq. 29-30)."""
    return 1 if scheme == "FLEX-DIAM" else 0


def exp2_chain_writes(scheme: str) -> int:
    """Experiment 2 — blockchain confirmations of one revocation workload.

    Same convention for every on-chain scheme: a workload of N revocations is
    confirmed by ONE commit, as FLEX-DIAM's single RevokeUsers transaction is.

    Ref [20]: 1 — the new accumulator value / membership change is published.
    Ref [24]: 0 — SRAA broadcasts the revocation polynomials via the RTA; the
              scheme has no blockchain, so there is nothing to confirm.
    Ref [28]: 1 — the revocation transaction is broadcast on the primary chain."""
    return 0 if scheme == "Ref [24]" else 1


def exp3_chain_reads(scheme: str) -> int:
    """Experiment 3 — on-chain READs inside one baseline access authentication
    (same grounding as exp1_chain_reads_per_auth)."""
    return 1 if scheme in ("Ref [20]", "Ref [28]") else 0
