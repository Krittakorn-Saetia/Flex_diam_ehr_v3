"""flex_diam.chain_meter — live calibration of blockchain unit costs.

Measures T_BC_write (one-key `Anchor`, submit -> commit) and T_BC_read (one-key
`GetAnchor` query) against the running chaincode with real `peer` calls. The
drivers use these units only for the BASELINE schemes' on-chain operations
(count * unit, counts in cost_model). FLEX-DIAM's own transactions are always
executed and timed for real. Nothing here is hard-coded.
"""

import secrets
import statistics


def calibrate(ledger, samples: int = 20) -> dict:
    """Measure write/read unit costs live. Returns means and stdevs in ms."""
    key = "cal_" + secrets.token_hex(4)
    writes = [ledger.anchor(key, secrets.token_hex(16))[1] for _ in range(samples)]
    reads = [ledger.get_anchor(key)[1] for _ in range(samples)]
    return {
        "write_ms": statistics.mean(writes),
        "write_stdev": statistics.pstdev(writes),
        "read_ms": statistics.mean(reads),
        "read_stdev": statistics.pstdev(reads),
        "samples": samples,
    }
