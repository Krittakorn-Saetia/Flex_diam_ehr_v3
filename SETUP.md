# Setup guide

How to go from a clean machine to running the three experiments. Follow the
steps in order; each one says what it does, what you should see, and how long it
takes.

| Step | What | Time | Needs |
|---|---|---|---|
| 1 | Ubuntu 22.04 and Docker | 15–30 min | admin rights, reboot on Windows |
| 2 | Get the code | 1 min | network |
| 3 | Install the toolchain and Hyperledger Fabric | 20–40 min | sudo, network |
| 4 | Build the project (circuits, keys, verifier) and check it offline | 2–3 min | network on first build |
| 5 | Start the blockchain network | 1 min | Docker running |
| 6 | Deploy the chaincode | 1 min | network on first build |
| 7 | Check the protocol on the live network | 1–2 min | — |
| 8 | Run the experiments | pilots: minutes; full: about 3 hours | — |

Steps 1–4 are done once per machine. Steps 5–7 are repeated whenever the
blockchain network has been shut down (for example after a reboot; see §9).

Everything below is typed in an **Ubuntu** terminal unless it says PowerShell.

---

## 1. Ubuntu 22.04 and Docker

**Hardware.** A 6-core CPU and 16 GB of RAM are enough (the published numbers
were measured on an Intel Core i5-10400F with 16 GB). About 10 GB of free disk.

### On Windows 11 (WSL2)

In an **administrator PowerShell**:

```powershell
wsl --install -d Ubuntu-22.04
```

Reboot if asked, then open "Ubuntu 22.04" from the Start menu and create the
Linux user. Install **Docker Desktop**, open Settings → Resources → WSL
Integration, and enable the Ubuntu-22.04 distribution.

### On native Ubuntu 22.04

Install Docker Engine (https://docs.docker.com/engine/install/ubuntu/) and allow
your user to run it without sudo:

```bash
sudo usermod -aG docker $USER
```

Log out and in again.

### Check

```bash
docker run --rm hello-world
```

It must print `Hello from Docker!`. If Ubuntu says `docker: command not found`
on Windows, Docker Desktop is not running or WSL integration is off.

---

## 2. Get the code

Clone **inside Ubuntu** (not on the Windows drive), so that scripts keep Unix
line endings and their executable bit:

```bash
git clone https://github.com/Krittakorn-Saetia/Flex_diam_ehr_v3.git ~/flex-diam-v3
```

All later commands assume the repository is at `~/flex-diam-v3`.

---

## 3. Install the toolchain and Hyperledger Fabric

```bash
cd ~/flex-diam-v3 && ./infra/setup_infra.sh
```

The script asks for your sudo password and downloads from the network. It is
safe to run again: a step whose result already exists is skipped.

| Step | Installs | Where |
|---|---|---|
| 1/6 | build tools, GMP, OpenSSL headers, `jq`, `rsync` | system (apt) |
| 2/6 | Go 1.22.5 | `/usr/local/go` |
| 3/6 | PBC 0.5.14 pairing library, built from source | `/usr/local/lib` |
| 4/6 | Python virtual environment, Charm-Crypto built from source, `cryptography`, `matplotlib`, `pyparsing` | `~/flex-diam/venv` |
| 5/6 | Node.js 18 (through nvm), Circom 2.1.9, SnarkJS 0.7.6 | `~/.nvm`, `~/bin/circom` |
| 6/6 | Hyperledger Fabric 2.5.9 binaries, Docker images and the test-network; sets the ordering service's BatchTimeout to 1 s | `~/flex-diam/fabric-samples` |

`~/flex-diam` is the infrastructure directory. To put it elsewhere, set
`FLEX_INFRA` before running the installer **and** in every later shell:

```bash
export FLEX_INFRA=/path/to/infra
```

**If you already have this environment** (for example from the earlier V2 code
base in `~/flex-diam`), skip this step. The experiments only need
`$FLEX_INFRA/venv` and `$FLEX_INFRA/fabric-samples`.

> This installer is the one used for the V2 code base, adapted to install into
> `$FLEX_INFRA`. The published results were measured on an environment built
> with the V2 installer; the adapted copy has not been run end to end on a fresh
> machine. If a step fails, the table above tells you what that step is meant to
> produce, and §11 lists the known problems.

### Open a new terminal, then check

The installer adds entries to `~/.bashrc`, and Ubuntu adds `~/bin` to the PATH
only at login. **Close the terminal and open a new one** before continuing.

```bash
cd ~/flex-diam-v3 && . ./env.sh && go version && node -v && circom --version && snarkjs --version | head -1 && peer version | grep Version && "$FLEX_PY" -c "from charm.toolbox.pairinggroup import PairingGroup; PairingGroup('BN254'); print('Charm OK')"
```

Expected (the versions the results were measured with):

```
go version go1.22.5 linux/amd64
v18.20.8
circom compiler 2.1.9
snarkjs@0.7.6
 Version: v2.5.9
Charm OK
```

### Check the BatchTimeout

Every on-chain write waits for the ordering service to cut a block, so this
value sets the latency of every transaction. The results use **1 s**; the
Fabric default is 2 s.

```bash
grep -n BatchTimeout ~/flex-diam/fabric-samples/test-network/configtx/configtx.yaml
```

It must show `BatchTimeout: 1s`. If it shows `2s`, change it:

```bash
sed -i 's/BatchTimeout: 2s/BatchTimeout: 1s/' ~/flex-diam/fabric-samples/test-network/configtx/configtx.yaml
```

The value is read when a channel is created. If the network is already up with
the old value, shut it down and bring it up again (§9).

---

## 4. Build the project and check it offline

```bash
cd ~/flex-diam-v3 && ./setup.sh
```

No Docker is needed for this step. What it does:

| Part | Result | Notes |
|---|---|---|
| circomlib | `zkp/node_modules/circomlib` | copied from `$FLEX_INFRA/zkp/node_modules` if present, otherwise `npm install` |
| helper circuit | `zkp/build/oracle_js/` | used to issue credentials and compute policy digests |
| credential-issuer key | `zkp/build/ci_key.json` | generated once; its public key is compiled into the circuit |
| authorization circuit | `zkp/build/authz.r1cs`, `authz_js/` | must report **3810 constraints, 3 public inputs** |
| Groth16 setup | `zkp/build/pot13_final.ptau`, `authz.zkey`, `authz_vk.json` | local powers-of-tau, 2^13 |
| native verifier | `zkp/batchverify_native/batchverify_native` | the first build downloads a Go 1.25 toolchain and gnark-crypto |
| proof corpus | `zkp/build/corpus/` (32 proofs) | used by Experiment 1 |
| verifier self-test | one JSON line | must contain `"selftest":"PASS"` |
| baseline self-test | 4 lines | all `[PASS]` |
| protocol check, in-memory ledger | 12 lines | ends with `12/12 checks passed` |

The end of a successful run looks like this:

```
{"backend":"gnark-native","corpus":32,"fs_bits":0,"selftest":"PASS","swapFp2":false}

=== baseline implementations ===
  [PASS] Ref [20] signature verifies
  [PASS] Ref [20] rejected for another message
  [PASS] Ref [20] rejected against a changed accumulator
  [PASS] Ref [24] revocation phase (update factor recovered, revoked twin blocked)

=== offline protocol check (in-memory ledger, no Docker) ===
  ...
12/12 checks passed
```

`zkp/build/` is not in the repository: each machine generates its own keys.
Deleting `zkp/build/ci_key.json` and re-running the build rotates the issuer key
and with it the verification key.

---

## 5. Start the blockchain network

Docker must be running.

```bash
cd ~/flex-diam/fabric-samples/test-network && ./network.sh up createChannel -c mychannel
```

This creates the certificates, starts one orderer and two peers (one per
organization), creates the channel `mychannel` and joins both peers. The output
ends with `Channel 'mychannel' joined`.

```bash
docker ps --format 'table {{.Names}}\t{{.Status}}'
```

must list `orderer.example.com`, `peer0.org1.example.com` and
`peer0.org2.example.com` as `Up`.

---

## 6. Deploy the chaincode

```bash
cd ~/flex-diam-v3 && ./chaincode/deploy_ccaas.sh
```

The chaincode runs as a service in its own container (`flexv3-chaincode`); the
peers connect to it. The script:

| Step | Action |
|---|---|
| 0 | checks that the peers, the orderer and the channel exist; stops with the command of §5 if they do not |
| 1 | builds the Docker image from `chaincode/flex/` (the first build downloads Go modules) |
| 2–4 | packages the chaincode, installs the package on both peers, reads the package ID |
| 5 | starts the chaincode container on the test-network's Docker network |
| 6–7 | approves the definition for both organizations and commits it (sequence 1) |
| 8 | queries the chaincode once |

A successful deployment ends with:

```
{"v_d":0,"v_p":0,"v_hs":0,"v_hd":0,"rl_d":false,"rl_hs":false,"rl_hd":false,"pid_ct":""}

=== ccaas deploy complete: chaincode 'flexv3' on channel 'mychannel' ===
```

That line is the scoped state of a request nobody has made: all versions zero,
nobody revoked.

After editing the Go code, rebuild and restart only the container:

```bash
IMAGE_ONLY=1 ./chaincode/deploy_ccaas.sh
```

---

## 7. Check the protocol on the live network

```bash
cd ~/flex-diam-v3 && . ./env.sh && "$FLEX_PY" smoke_protocol.py
```

This runs the complete protocol against Fabric: registration, encryption,
authorization with a real proof, delegation, release, decryption, and every
revocation scope. It takes one to two minutes because each write waits for a
block. It must end with:

```
12/12 checks passed
```

Do not start the experiments before this passes.

---

## 8. Run the experiments

Short pilots first (a few minutes; output goes to `*_PILOT.csv`):

```bash
PILOT=1 ./run_exp1.sh && PILOT=1 ./run_exp2.sh && PILOT=1 ./run_exp3.sh
```

Things to look at in the pilot output:

- `T_BC write` should be close to 1,100 ms. A value near 2,100 ms means the
  channel was created with the 2 s BatchTimeout (§3).
- Experiment 3 lines for N > 0 should end with
  `continuity=1, revoked rejected=1`.

Then the full experiments, 30 independent runs each:

```bash
./repeat_exp1.sh && ./repeat_exp2.sh && ./repeat_exp3.sh
```

| Experiment | Per run | 30 runs |
|---|---|---|
| 1 — authorization throughput | about 1 min | about 30 min |
| 2 — scoped user revocation | about 3 min | about 1.5 h |
| 3 — unaffected-user continuity | about 2 min | about 1 h |

- Run them one after another, never in parallel: they share the ledger and the
  CPU.
- Keep the machine awake and otherwise idle.
- If results from an earlier set of runs are in the directory, each script moves
  them to `results_archive/<timestamp>_expN/` before it starts.
- The chained command stops at the first failure; completed per-run files stay
  on disk.

Figures:

```bash
. ./env.sh && "$FLEX_PY" plot_figs.py
```

Outputs, switches and the meaning of each column are described in
[README.md](README.md).

---

## 9. Stopping, and starting again later

**Shut the network down** (removes its containers, volumes and certificates):

```bash
cd ~/flex-diam/fabric-samples/test-network && ./network.sh down
```

```bash
docker rm -f flexv3-chaincode
```

**Start again** (also after a reboot or a Docker restart, which leaves the
containers stopped): run the two shutdown commands above first — they are
harmless if nothing is running — then repeat steps 5, 6 and 7. Bringing the
network up creates a **new, empty ledger**, so the chaincode has to be deployed
again. Steps 1–4 are not repeated; `zkp/build/` is kept.

---

## 10. What is where after setup

```
~/flex-diam/                      infrastructure ($FLEX_INFRA)
    venv/                         Python + Charm-Crypto
    fabric-samples/test-network/  Fabric network scripts, certificates, channel artifacts
    fabric-samples/bin/           peer, orderer, configtxgen, ...
    charm/, pbc-0.5.14/           sources built by the installer

~/flex-diam-v3/                   this repository
    zkp/build/                    circuits, keys, proof corpus        (generated)
    zkp/batchverify_native/batchverify_native                         (generated)
    exp*_*.csv, fig/              results of your runs                (generated)
    results_archive/              earlier results moved aside         (generated)
```

`env.sh` connects the two: it sets the Fabric paths and peer identity
(organization 1 administrator), loads nvm, and defines `FLEX_PY`, the Python
interpreter of the virtual environment. Every script sources it.

---

## 11. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `docker: command not found` (Windows) | Docker Desktop is not running, or WSL integration is off for Ubuntu-22.04. |
| `permission denied` talking to Docker (Linux) | `sudo usermod -aG docker $USER`, then log out and in. |
| Installer stops at Charm with `openssl/objects.h: No such file` | Run `./infra/setup_infra.sh` again; step 4 passes the include path through sudo. |
| `circom: command not found` or `snarkjs: command not found` after the installer | Open a new terminal (PATH and nvm are set at login). |
| `setup.sh`: Go reports that gnark-crypto requires a newer Go | Go must be allowed to fetch its toolchain: `go env -w GOTOOLCHAIN=auto`, with network access, then run `setup.sh` again. |
| `Cannot run peer because cannot init crypto ... msp ... does not exist` | The Fabric network is down. Do steps 5 and 6. |
| `connection refused` on port 7050, 7051 or 9051 | Same: the network containers are not running. |
| Deployment says the chaincode definition is already committed, or asks for another sequence number | The chaincode is already deployed on this ledger. Check with `docker ps`; to start clean, do §9 and deploy again. |
| `T_BC write` near 2,100 ms | BatchTimeout is 2 s. Fix it (§3), then shut down and restart the network (§9). |
| A write or query fails with an error saying the chaincode could not be launched or reached | The chaincode container is not running: `docker ps` should list `flexv3-chaincode`. Run `IMAGE_ONLY=1 ./chaincode/deploy_ccaas.sh`. |
| `ZK.Prove failed` in the live check | `zkp/build/` is missing or incomplete; run `./setup.sh` again. |
| `argument ... exceeds the single-argument limit of the peer CLI` | A workload is too large for one transaction; use a smaller one or `REVOKE_MODE=per_tx`. |
| `$'\r': command not found` when running a script | The repository was checked out on Windows with CRLF line endings. Clone inside Ubuntu (§2). |
