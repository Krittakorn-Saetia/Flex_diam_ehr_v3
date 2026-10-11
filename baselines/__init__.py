"""baselines — cost-dominant operations of comparison schemes.

Implements only the COST-DOMINANT operations from each baseline paper, on the
same pairing group as FLEX-DIAM (FLEX_CURVE, default BN254), so the comparison
is fair. Full protocol
reproduction is explicitly out of scope (stated in NOTES_cost_dominant_ops.md
and the paper's experimental section).

Modules:
- zeng [20]: dynamic accumulator + group signature (TIFS 2025)
- li   [24]: bivariate symmetric polynomial broadcast (TII 2026)
- wang [28]: chameleon-hash CRL on certificateless ECC (TCSS 2024)
"""
