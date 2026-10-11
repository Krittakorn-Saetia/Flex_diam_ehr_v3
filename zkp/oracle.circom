pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/babyjub.circom";

// Witness-only helper (never proven). The credential issuer and the data owner
// need the SAME Poseidon and Baby-Jubjub arithmetic as authz_template.circom to
// issue a VC (eq. 5) and to compute pid (eq. 10). Evaluating them through this
// circuit's witness calculator guarantees bit-for-bit agreement with the
// circuit and avoids a second, hand-written implementation of either primitive.
//
//   Ax, Ay    = a * Base8                       (pk_CI for secret a)
//   R8x, R8y  = r * Base8                       (EdDSA nonce commitment)
//   m         = Poseidon(attrs, did, texp)      (VC digest)
//   h         = Poseidon(R8x, R8y, Ax, Ay, m)   (EdDSA challenge)
//   pid       = Poseidon(req)                   (policy digest)
//
// The caller finishes the signature as S = (r + 8*h*a) mod l.
template Oracle(NA, NP) {
    signal input a;
    signal input r;
    signal input attrs[NA];
    signal input did;
    signal input texp;
    signal input req[NP];

    signal output Ax;
    signal output Ay;
    signal output R8x;
    signal output R8y;
    signal output m;
    signal output h;
    signal output pid;

    var i;

    component pkA = BabyPbk();
    pkA.in <== a;
    Ax <== pkA.Ax;
    Ay <== pkA.Ay;

    component pkR = BabyPbk();
    pkR.in <== r;
    R8x <== pkR.Ax;
    R8y <== pkR.Ay;

    component vcHash = Poseidon(NA + 2);
    for (i = 0; i < NA; i++) {
        vcHash.inputs[i] <== attrs[i];
    }
    vcHash.inputs[NA] <== did;
    vcHash.inputs[NA + 1] <== texp;
    m <== vcHash.out;

    component chal = Poseidon(5);
    chal.inputs[0] <== R8x;
    chal.inputs[1] <== R8y;
    chal.inputs[2] <== Ax;
    chal.inputs[3] <== Ay;
    chal.inputs[4] <== m;
    h <== chal.out;

    component polHash = Poseidon(NP);
    for (i = 0; i < NP; i++) {
        polHash.inputs[i] <== req[i];
    }
    pid <== polHash.out;
}

component main = Oracle(4, 4);
