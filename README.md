# Generic Groth16 (SP1) Verifier for State Transition and Consensus Proofs
This repo is a prototype / POC of a generic SP1 proof verifier module that extends [Celestia app](https://github.com/celestiaorg/celestia-app/tree/feat/ethereum-consensus).
The new branch is based off the [ZKISM branch](https://github.com/celestiaorg/celestia-app/tree/feature/zk-execution-ism) that we created for evolve block proofs and can be found [here](https://github.com/celestiaorg/celestia-app/tree/feat/ethereum-consensus).

## Motivation and Context
In order for Celestia to become a hub for connecting all sorts of different chains, we must ensure the availability of trusted state roots.
Each consensus model may require its own implementation of a consensus client, but it will practically always be a transition from previous_trusted_state to new_trusted_state.
The `Verifier` module that was added to `celestia-app` for this POC allows anyone to deploy an on-chain verifier for SP1 Groth16 State Transition proofs, enabling Celestia
to serve trusted roots for all kinds of different chains (Solana, Ethereum, L2s, ...).

## Limitations

### Celestia
Since Celestia is not a Smart Contract platform, this POC does not include an execution context and only verifies the proofs to update the trusted state.
The scope of this project is limited to the availability of ZK-verified data roots on Celestia.

### Groth16
Currently the verifier only supports SP1 Groth16 proofs that require 2 verifying keys, one that is project specific and a wrapper key specific to SP1.
Risc0 works similarly but is not supported out of the box because of differences in versioning. It should be possible to extend the verifier to 
support Risc0 by ignoring the versioning.

For generic (non-ZKVM) Groth16 proofs, we will have to extend the implementation to handle cases where there is just one verifying key and call the 
Groth16 verifier directly. However it seems likely that most ZK light client that we will integrate use SP1, Risc0 or another ZKVM that has a dual verifying-key requirement.


## Instructions to run the POC

1. Clone the repo
```bash
git clone git@github.com:celestiaorg/mock-zk-consensus-client
```

2. Clone the celestia-app fork
```bash
git clone git@github.com:celestiaorg/celestia-app
cd celestia-app
git checkout feat/ethereum-consensus
git pull
./build.sh

cd mock-zk-consensus-client
docker compose up
```

To stop the celestia-validator node:
```bash
docker compose down -v
```

This will build the `celestia-app-standalone` docker image locally.

3. Run the binary

The binary will:

- create a new Generic State Transition Verifier from the ZKISM module
- generate a ZKP using the mock client (real SP1 Groth16 proof)
- submit the proof and update the Trusted State Bytes in the Verifier module instance

```bash
cargo run -p project --release
```

4. Query for results

You can query the verifier at any time using:

```bash
docker exec -it celestia-validator /bin/bash
celestia-appd q zkism verifiers
```

This will list all verifiers (should be one) and also show their trusted state.
The expected trusted state after running the `project` binary is `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=`.