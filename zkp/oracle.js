// zkp/oracle.js — evaluate oracle.circom through its wasm witness calculator.
//
//   node oracle.js eval          JSON input on stdin -> JSON outputs on stdout
//   node oracle.js ci-keygen F   write a fresh credential-issuer key to file F
//
// FLEX_ZKP_BUILD overrides the build directory (default: ./build).
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const BUILD = process.env.FLEX_ZKP_BUILD || path.join(__dirname, "build");
const OUTPUTS = ["Ax", "Ay", "R8x", "R8y", "m", "h", "pid"];
// Order of the Baby-Jubjub prime subgroup (circomlib eddsaposeidon.circom
// compares S against this value minus one).
const SUBORDER = 2736030358979909402780800718157159386076813972158567259200215660948447373041n;

async function evaluate(input) {
  const wc = require(path.join(BUILD, "oracle_js", "witness_calculator.js"));
  const wasm = fs.readFileSync(path.join(BUILD, "oracle_js", "oracle.wasm"));
  const calc = await wc(wasm);
  const w = await calc.calculateWitness(input, 0);
  const out = {};
  OUTPUTS.forEach((name, i) => { out[name] = w[i + 1].toString(); });
  return out;
}

function randomScalar() {
  for (;;) {
    const v = BigInt("0x" + crypto.randomBytes(32).toString("hex")) % SUBORDER;
    if (v > 0n) return v;
  }
}

async function main() {
  const mode = process.argv[2];
  if (mode === "eval") {
    const input = JSON.parse(fs.readFileSync(0, "utf8"));
    console.log(JSON.stringify(await evaluate(input)));
  } else if (mode === "ci-keygen") {
    const a = randomScalar();
    const out = await evaluate({
      a: a.toString(), r: "1", attrs: ["0", "0", "0", "0"], did: "0", texp: "0",
      req: ["0", "0", "0", "0"],
    });
    fs.writeFileSync(process.argv[3], JSON.stringify({ a: a.toString(), Ax: out.Ax, Ay: out.Ay }));
    console.log("credential-issuer key written to " + process.argv[3]);
  } else {
    console.error("usage: oracle.js eval | ci-keygen <file>");
    process.exit(2);
  }
}

main().catch((e) => { console.error(e); process.exit(1); });
