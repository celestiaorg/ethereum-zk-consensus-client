# Integration steps for SP1 Helios (Ethereum ZK Light Client)

Looking at the ProofInputs and ProofOutputs of [Sp1 Helios](https://github.com/succinctlabs/sp1-helios/blob/main/program/src/light_client.rs), we can slightly modify them such that the proofs can be verified by our Celestia StateTransitionVerifier.

## ProofInputs
```
    let ProofInputs {
        updates,
        finality_update,
        expected_current_slot,
        mut store,
        genesis_root,
        forks,
        contract_storage,
    } = serde_cbor::from_slice(&encoded_inputs).unwrap();
```

Keep as-is for the most part, but introduce a new TrustedState struct that encapsulates the relevant fields: 

```rust
TrustedState{
    executionStateRoot: *execution.state_root(),
    newHeader: header,
    executionBlockNumber: U256::from(*execution.block_number()),
    nextSyncCommitteeHash: next_sync_committee_hash,
    newHead: U256::from(head),
    prevHeader: prev_header,
    prevHead: U256::from(prev_head),
    syncCommitteeHash: sync_committee_hash,
    prevSyncCommitteeHash: prev_sync_committee_hash,
}

```

Looking at the program inputs:

```rust
    let ProofInputs {
        updates,
        finality_update,
        expected_current_slot,
        mut store,
        genesis_root,
        forks,
        contract_storage,
    } = serde_cbor::from_slice(&encoded_inputs).unwrap();
```

Where `store` encapsulates the trusted state, e.g. `current_sync_committee`, `finalized_header` and `next_sync_committee`. 

Adding TrustedState to the ProofInputs and modifying the verification logic slightly, such that the other inputs are verified against the fields from TrustedState and committing as output the concatenated bytes of the input TrustedState and output TrustedState,

```
public_outputs = length_prefix || trusted_state || new_trusted_state
```


will enable the integration of this Light Client with the Celestia verifier.

The only places where the verification logic must be modified are where headers and committee hashes are computed inside the circuit, from the outputs.

Apply changes like this:

```rust
    let prev_sync_committee_hash = store.current_sync_committee.tree_hash_root();
    ...
```

to 

```rust
    let prev_sync_committee_hash = store.current_sync_committee.tree_hash_root();
    assert_eq!(prev_sync_committee_hash, trusted_state.prev_sync_committee_hash)
```

wherever `.tree_hash_root()` is used and assert that the previous height used in the circuit always matches that from the addtional TrustedState input.
