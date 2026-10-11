# Paper → code record — FLEX-DIAM V3

How the implementation in this repository follows the FLEX-DIAM paper
(scoped-revocation revision, October 2026), equation by equation, and what was
chosen where the paper leaves a detail open. Measured results, the experiment
method and the validation evidence are in [REPORT.md](REPORT.md).

Rule followed throughout: **the paper is the specification.** Where the paper
states something, the code does that. Where it is silent, a choice was made and
is listed in §2.

## 1. Paper → code

| Paper | Code |
|---|---|
| Eq. 1 CPABE.Setup | `abpre.ABPRE.setup`, called in `protocol.FlexDiam.__init__` |
| Eq. 2–3 keys, DID = H(pk), on-chain registration | `protocol.new_entity`, `FlexDiam.register`; chaincode `RegisterDID` |
| Eq. 4–5 Attr_D, VC_D = Sign_skCI(Attr ‖ DID ‖ t_exp) | `zkp.issue_vc` |
| Eq. 6 SK_D | `abpre.ABPRE.keygen`, `FlexDiam.enroll_doctor` |
| Eq. 7 RS = ⟨RL, {v_D}, {v_p}, {v_H}⟩ | chaincode keys `rl_`, `vd_`, `vp_`, `vh_` (absent = 0) |
| Eq. 8–12 K_AES, CT_m, pid, CT_k, CT | `FlexDiam.encrypt_ehr`, `zkp.policy_pid`, `abpre.encrypt_key` |
| Eq. 13–14 Meta, Com | `FlexDiam.encrypt_ehr`; chaincode `RegisterMetadata` |
| Eq. 15 Req_i | `protocol.Req` |
| Eq. 16–17 σ_i, ρ_i | chaincode `ResolveState`; `protocol.scoped_digest` |
| Eq. 18 Valid_rev | `FlexDiam.valid_rev` |
| Eq. 19–22 x_i, w_i, π_i, relation | `zkp/authz_template.circom`, `zkp.prove` |
| Eq. 23–26 batch, η_B, r_i, BatchVerify, recursive partition | `zkp/batchverify_native/main.go` (`coeffs`, `fsCoeff`, `batchVerifyWith`, `resolve`) |
| Eq. 27 Valid_auth | `FlexDiam.authorize_batch`, `FlexDiam.access` |
| Eq. 28 AuthTok_i | `protocol.AuthTok`, `FlexDiam.issue_token` |
| Eq. 29–30 BatchCom anchor | `FlexDiam.anchor_batch`; chaincode `AnchorBatch` |
| Eq. 31–34 DelReq, σ_cur, ρ_cur, Valid_del | `FlexDiam.delegate_and_release`, `FlexDiam.valid_del` |
| Eq. 35 DAC_i (t_del ≤ t_exp) | `protocol.DAC`, `FlexDiam.issue_dac` |
| Eq. 36–37 ctx_i, ReKeyGen | `FlexDiam.context`, `FlexDiam.kms_rekeygen`, `abpre.rekeygen` |
| Eq. 38–39 correctness / ⊥ on ctx′ ≠ ctx | `abpre.redec`; `smoke_protocol.py` check 6 |
| Eq. 40–41 ReEnc, C̃T | `FlexDiam.proxy_reenc`, `abpre.reenc` |
| Eq. 42 DelCom | `FlexDiam.delegation_audit`; chaincode `RecordDelegation` |
| Eq. 43–45 Valid_acc, release | `FlexDiam.cloud_release`, `FlexDiam.valid_acc` |
| Eq. 46–48 ctx*, ReDec, AEAD.Dec | `FlexDiam.doctor_recover` |
| Eq. 49 AccCom | `FlexDiam.access_audit`; chaincode `RecordAccess` |
| Eq. 50 RL ∪ {DID_Di}, v_Di + 1 | chaincode `RevokeUser`, `RevokeUsers` |
| Policy / domain scope | chaincode `RevokePolicy`, `RevokeDomain` |

## 2. Choices made where the paper is silent

| # | Topic | Choice |
|---|---|---|
| C1 | Hash H and "‖" | SHA-256 over length-prefixed components. Exception: pid and the VC digest use Poseidon, because eq. 22 must check them inside the circuit. |
| C2 | Policy A in the ZKP | Conjunctive policies only (AND of up to 4 attributes; a credential holds up to 4). CP-ABE itself accepts any Charm policy. |
| C3 | VC signature | EdDSA-Poseidon on Baby-Jubjub (circomlib). pk_CI is a constant of the circuit, so x_i is exactly ⟨DID, pid, ρ⟩ as in eq. 19. |
| C4 | ABPRE construction | BSW07 CP-ABE plus a KMS-issued blinded transformation key; the blinding factor is derived from ctx and delivered under the policy. Details in `flex_diam/abpre.py` and REPORT.md §4.4. No security proof is claimed for this instantiation. |
| C5 | Sign_skSC | ECDSA P-256 / SHA-256. |
| C6 | AEAD | ChaCha20-Poly1305 (the architecture figure names it). `FLEX_AEAD=aesgcm` selects AES-256-GCM. |
| C7 | Exp 2 transaction shape | One `RevokeUsers` transaction per workload (one confirmation). `REVOKE_MODE=per_tx` submits one transaction per doctor instead. |
| C8 | Exp 2 baseline confirmations | One commit per workload for Refs [20] and [28], none for Ref [24] (SRAA has no blockchain). Same convention as C7. |
| C9 | Batch window in Exp 3 | b = 1 and Δ_b = 0: the batch closes immediately. Any Δ_b > 0 would add directly to FLEX-DIAM's latency. |
| C10 | Lifetimes | t_exp = now + 600 s, t_del = min(now + 120 s, t_exp). |
| C11 | Who reads the chain | Every role that validates the current scoped state does its own read: authorization service, delegation service, KMS, proxy, cloud. That is 5 reads and 2 audit writes inside the timed window of Exp 3, all synchronous. |
| C12 | Coefficients r_i | Full scalar-field width, as eq. 25 states. `FLEX_FS_BITS=128` gives small-exponent batching. |
| C13 | "30 independent runs" | `repeat_*.sh`: REPEATS=30 full runs, one measurement per point per run for Exp 2–3. |
| C14 | Revoked doctors | Fresh identities, registered on chain, then revoked. |
| C15 | Baseline "access" in Exp 3 | Client side + server side of one authentication, plus the scheme's on-chain read. Ref [28]'s client cost follows its Table I (6 T_sm + 4 T_h + 3 T_pa). |
| C16 | Chaincode name | `flexv3`. |
| C17 | Ref [24] update rounds | A workload of N revocations is processed as N gateway update rounds of one twin each (`SRAA_BATCH=1`). The sensitivity to this choice is in REPORT.md §6.2. |

## 3. Scope of the prototype

- All measurements were made on one machine (Intel Core i5-10400F, 16 GB RAM,
  Windows 11 + WSL2 Ubuntu 22.04). Exact versions are in REPORT.md §7.1.
- DIDs are registered on the Fabric chaincode, as Phase 1 Step 2 describes.
  Credentials are issued by a local credential issuer. No separate DID ledger
  (such as Hyperledger Indy) is used.
- Ten hospital DIDs are registered. A population of 1,000 professionals and
  50,000 records is not instantiated; no measured operation depends on it.
- All roles run in one process. Blockchain calls go through the `peer` CLI, so
  each read and write includes process start-up.
- ZK.Prove is `snarkjs groth16 fullprove`; its time includes Node start-up.
- Credential expiry is not checked inside the circuit (eq. 22 does not list it).
- Encrypted storage is an in-process dictionary.
- The compared schemes are not full protocol implementations. Ref [20]'s group
  signature and Ref [24]'s revocation phase are implemented in full and
  self-checked; Ref [28] and Ref [24]'s authentication are cost-dominant
  operation models (`NOTES_cost_dominant_ops.md`).

## 4. Technical notes

**N1 — Chain reads in the Experiment 1 model.** Experiment 1 charges Refs [20]
and [28] one on-chain read per request and charges FLEX-DIAM one batch-anchor
write per verification window and no per-request read. Phase 3 Step 1 has the
authorization service resolve σ_i from the blockchain for each request; that
read is executed for real in Experiment 3 but is not part of the Experiment 1
throughput model. This is a stated assumption of that model
(`cost_model.exp1_chain_reads_per_auth`).

**N2 — Consortium size.** Experiment 2 measures the revoking authority and
Experiment 3 one unaffected user, so the number of users in the consortium does
not enter either result.

**N3 — Ref [20].** Zeng's Verify uses the accumulator value inside the signature
equation (three pairings in total); there is no separate membership check.
`baselines/zeng.py` implements Sign and Verify as that paper states them. The
evidence update follows Zeng's Update: N field multiplications and one G2 scalar
multiplication for N revocations.

**N4 — Ref [24].** SRAA's revocation phase is executed in full on a real
polynomial: the gateway builds Φ, expands Ψ(θ) = u·Φ(θ) + f(θ, Φ(θ)) and updates
f; each twin evaluates Φ and Ψ at its identity to recover u. With f of degree
t = 100, Ψ has t·(m+1)+1 coefficients for a round revoking m twins, and its
expansion costs about t²m²/2 field operations, so the grouping of revocations
into rounds matters (choice C17). SRAA states that the number of twins per domain
is bounded by t; workloads up to 2,000 are outside that bound with t = 100.

**N5 — Forward revocation.** A revoked doctor keeps a CP-ABE key that satisfies
the policy. Revocation holds because no fresh transformed key material is
released to that doctor; it relies on the cloud and the proxy never handing out
the stored CT_k directly.

**N6 — pk_Hd in ReKeyGen.** ReKeyGen takes pk_Hd (eq. 37) while ReDec uses only
SK_Di (eq. 47). Here pk_Hd is bound into the blinding factor; no domain secret
key takes part in decryption.

**N7 — Ledger state across runs.** Revoked DIDs from earlier runs stay on the
ledger. All lookups are keyed, so they are not on the measured path, but "N = 0"
means "none revoked among this run's identities".

**N8 — Differences from the V2 measurement of Experiment 1.** The V3 circuit has
three public inputs (V2: two) and the verifier derives full-width Fiat–Shamir
coefficients (V2: 128-bit random coefficients, the first fixed to 1). The V2
data is kept in `results_v2_exp1/` for comparison.
