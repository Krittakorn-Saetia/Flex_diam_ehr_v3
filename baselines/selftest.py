#!/usr/bin/env python3
"""baselines/selftest.py — functional checks of the baseline implementations.

    $FLEX_PY -m baselines.selftest

Ref [20]: a group signature verifies; it fails for another message and against
          an accumulator value the signer's evidence does not match.
Ref [24]: in the revocation phase a legitimate twin recovers the gateway's
          update factor and ends with the slice of the new polynomial, while a
          revoked twin cannot update.
"""

import sys

from charm.toolbox.pairinggroup import G2

from baselines import li, zeng


def main() -> int:
    sig = zeng.sign()
    checks = [
        ("Ref [20] signature verifies", zeng.verify(sig)),
        ("Ref [20] rejected for another message", not zeng.verify(sig, msg=b"another message")),
        ("Ref [20] rejected against a changed accumulator",
         not zeng.verify(sig, acc=zeng._group.random(G2))),
    ]
    try:
        li.selftest()
        checks.append(("Ref [24] revocation phase (update factor recovered, revoked twin blocked)", True))
    except AssertionError as e:
        checks.append((f"Ref [24] revocation phase: {e}", False))
    for name, ok in checks:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    return 0 if all(ok for _, ok in checks) else 1


if __name__ == "__main__":
    sys.exit(main())
