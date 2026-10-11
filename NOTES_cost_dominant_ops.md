# Cost-dominant operations per scheme — notes from PDF read (Day 1)

> **V3 addendum (2026-10-12).** This note is the V2 planning document and is kept
> for history; three things in it no longer describe the code.
>
> 1. **FLEX-DIAM** no longer advances a global epoch. Revocation is scoped
>    (per-user, per-policy, per-domain versions); see `PAPER_FIDELITY.md`.
> 2. **Ref [20]**: the separate accumulator check `T_ACC` listed below is not
>    part of Zeng's scheme and is no longer charged. `baselines/zeng.py` now
>    implements Zeng's Sign / Verify exactly.
> 3. **Ref [24]**: the revocation phase is now executed in full, including the
>    gateway's expansion of Ψ and the twin's evaluation of Ψ, which the V2 code
>    left out. The "× M users" aggregation of this note is also gone: the revised
>    paper charges the authority in Experiment 2 and one unaffected user in
>    Experiment 3.


Source PDFs in `../Flex_diam_ehr_v2_material/`. This file is the implementation contract for Days 2–5: each row below is what we will actually measure on the i5-10400F.

## Symbols (from FLEX-DIAM Table II)

| Symbol | Meaning |
|---|---|
| `T_sm` | Elliptic curve scalar multiplication |
| `T_pa` | EC point addition |
| `T_h` | Hash (SHA-256) |
| `T_bp` | Bilinear pairing |
| `T_e`  | Modular exponentiation in finite field |
| `T_BC` | Blockchain TX submit→commit |
| `T_SC` | Smart-contract execution (no state change) |
| `T_Epoch` | FLEX-DIAM epoch advancement = 1 Fabric chaincode invoke that increments an integer |

## Fig 4 — Post-Revocation Update Latency (cumulative for N revocations)

| Scheme | What we measure per N | Expected shape | Source |
|---|---|---|---|
| **Ref [20] Zeng** | For each remaining user (pool size M=1000): `w = ∏_{j∈S_1}(s_j + x)` (N field mults in Z_q) then `W'_i = w · W_i` (1× `T_sm` in G2). Plus N accumulator updates by GM: each `ACC_{j+1} = (s*+x)^{-1} · ACC_j` = 1 inversion + 1× `T_sm` in G2. Total: ~`M·(N field mults + T_sm) + N·(inv + T_sm)`. | ~linear in N (M dominates the witness redistribution) | Zeng §IV.Update + §V.C, Algorithm in Revoke/Update |
| **Ref [24] Li** | GW: `Φ(θ) = ∏(θ - MID_i)` of degree N (N polynomial multiplications); `Ψ(θ) = u·Φ(θ) + f(θ, Φ(θ))` (polynomial composition with degree-t bivariate `f`, t=100 per their paper). Each DT in pool: evaluate `Φ(PID)` (N mults), `g_i(Φ(PID))` (degree-t polynomial eval), compute `u`, then `g'_i(y) = u·g_i(y)` ((t+1) field mults). Total: `O(M·(N + t))` field ops + 1 broadcast. | ~linear in N, slope shallower than [20] because field ops < scalar mults | SRAA §IV.C.5 "DT Revocation Phase" |
| **Ref [28] Wang** | Per revocation: chameleon-hash forge = `3·T_sm + T_h + T_pa` (paper's own number). Cumulative N revocations: `N·(3·T_sm + T_h + T_pa)`. Plus 1 hash add to blacklist tree per revocation. | strictly linear in N, slope = `3·T_sm + T_h + T_pa` per revoke | Wang §V.C "identity revocation" closed-form |
| **FLEX-DIAM** | 1× `T_Epoch` = single Fabric chaincode TX that does `Epoch ← Epoch + 1`. Independent of N. | flat horizontal line | FLEX-DIAM §III.C Phase "Revocation Management" Step 3, eq. (39) |

**Implementation choice for Ref [20] and [24]**: we use M = 1000 (matches FLEX-DIAM's stated consortium scenario of "1,000 healthcare professionals"). The witness-redistribution and polynomial-broadcast costs are *per remaining user*, so M is a load multiplier. If we don't honestly load it across M users, we'd be measuring the GM-side cost only and missing the scheme's real burden — which is exactly the point of Fig 4. We will measure both single-user cost and aggregate (× M) cost; the CSV cell will be the aggregate.

## Fig 5 — Cross-Domain Sharing Latency (N records, end-to-end)

| Scheme | Per-record cost | Per-session setup | Expected shape | Source |
|---|---|---|---|---|
| **Ref [20]** | Per record: `T_S^GS + T_V^GS + T_ACC + T_BC` ≈ group sig gen (multi-pairing) + verify (multi-pairing) + accumulator membership check + 1 blockchain TX. Pairings dominate. | none material | linear in N, steep slope (pairings + chain TX per record) | Zeng §V.B |
| **Ref [24]** | Their paper reports `11.71n + 0.77 ms` for full cross-domain access phase with n records on their i7-11700X. On our i5-10400F (~similar arch, slightly slower), expect ~13–16n + 1 ms. We re-measure honestly — do not copy their number. | `0.77 ms` constant on their hw | linear in N | SRAA §VI.A reported, §IV.C.4 protocol |
| **Ref [28]** | Per record: `T_V^CL + T_BC` ≈ certificateless verify (point mults + hash) + blockchain TX for state. | none material | linear in N | Wang §IV.D + Table I |
| **FLEX-DIAM** | Per-record cost = ABPRE re-encryption of key component only (1 re-key operation per record) + AEAD decrypt. Authn (ZKP) is done **once per session**, not per record. | Per-session: ZKP prove + verify + DAC issuance (1 Fabric TX) + 1× `T_SC`. | linear in N with high intercept + low slope; crosses below baselines around N ≈ 50 | FLEX-DIAM §III.C Phase 4 |

**Why FLEX-DIAM crosses baselines around N≈50**: the per-session setup (ZKP + DAC) is expensive (~50–200 ms on our hw, mostly ZKP) but is amortized across N records. The baselines have ~0 setup but each per-record cost includes authn. So FLEX-DIAM beats them once N × (per-record-authn-baseline) > setup-FLEX. With per-record-baseline ~5–15 ms, crossover is at N ≈ 10–40.

## Hardware sanity-check baseline (we will measure on Day 2)

Use these as guard rails. If our measured numbers are >2× off, something is wrong.

| Op | Ref [24] on i7-11700X | Ref [28] on i5-10300H | Our target on i5-10400F |
|---|---|---|---|
| `T_sm` (EC scalar mult) | 0.383 ms | 0.897 ms | 0.7–1.2 ms |
| `T_h` (SHA-256) | 0.004 ms | ~0.002 ms | 0.002–0.005 ms |
| `T_pa` (EC add) | n/a | 0.008 ms | 0.005–0.015 ms |
| `T_e` (mod exp) | 0.689 ms | 2.697 ms | 1.5–3.0 ms |
| `T_bp` (bilinear pairing) | n/a | 3.544 ms | 3–6 ms |
| `T_BC` (Fabric TX submit→commit) | n/a (they use 5.26 ms smart contract read) | n/a | 1000–3000 ms on local test-network |

The i5-10300H in Ref [28] is closest to our i5-10400F — useful direct comparison. (10300H is laptop, 10400F is desktop, but same Comet Lake gen.)

## Scope reductions from the paper's claimed stack — must be documented

The conference draft §IV.B.1 claims:
- "approximately 5,200 lines of Python and Solidity" — **we have 0 lines today**. Will be more like 1500–2500 lines after Day 5.
- "Intel Xeon Silver 4314, 64 GB RAM, Ubuntu 24.04" — **we run on i5-10400F, 16 GB, WSL2 Ubuntu 22.04**. Paper text update required.
- "Hyperledger Indy components" for DIDs/VCs — **we will substitute** Ed25519 keypairs + Fabric chaincode registry. Honest approximation: a DID is just an identifier bound to a public key registered on a verifiable log; Fabric chaincode satisfies the requirement. Cost-dominant ops (sign/verify) are equivalent.
- "Circom + SnarkJS" for zk-SNARK — **OPEN QUESTION**, see below.
- "Charm-Crypto" for CP-ABE/ABPRE — matches plan ✓
- "Hyperledger Fabric 2.5" — matches plan ✓

Each substitution will be stated in the experimental setup section we update on Day 6.

## OPEN QUESTIONS for the user (block Day 2 crypto work)

**Q1: ZKP implementation choice for FLEX-DIAM authn.**

Options:
- (a) **Circom + SnarkJS** — matches paper exactly, but adds Node.js to the stack and Circom circuit-writing time (~1 day of work alone). Groth16 proof gen ~50 ms, verify ~5 ms on our hardware.
- (b) **Schnorr ZKP in Charm-Crypto** — simpler, pure Python+Charm, ~5 ms prove + ~5 ms verify. Not a zk-SNARK (proof size is ~256 B vs ~200 B Groth16), but is a valid NIZK via Fiat-Shamir. Document as scope reduction: "We implement the ZKP authentication using Schnorr-style proof of knowledge of credential signature, achieving the same zero-knowledge property at lower computational cost than the originally specified zk-SNARK design."
- (c) **py_ecc / pysnark Python Groth16** — closer to (a) without Node, but pysnark is unmaintained and the install is finicky.

**Recommendation: (b) Schnorr in Charm.** It's defensible, fast, and lets us focus the timeline on the FLEX-DIAM-specific contributions (epoch mechanism, DAC, ABPRE). Affects Fig 5 numbers only; the comparison still tells the story.

**Q2: DID/VC substitution.**

The paper says Hyperledger Indy. Indy is a separate blockchain — installing it alongside Fabric in WSL doubles our blockchain footprint. Substitute with Ed25519 keypairs + Fabric chaincode DID registry?

**Recommendation: yes, substitute.** No experimental finding hinges on the difference; this is a stack simplification, not a protocol change. Cost-dominant ops are sign/verify, same complexity class.

---

Once you answer Q1 and Q2, I have everything I need to write the crypto code on Day 2.
