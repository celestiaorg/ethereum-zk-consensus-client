#![no_main]

use alloy_sol_types::SolValue;
use sha2::{Digest, Sha256};
use sp1_helios_primitives::types::ProofOutputs;
use types::{RecursionInput, TrustedState};

sp1_zkvm::entrypoint!(main);

pub fn main() {
    // take proof and previous trusted state
    // assert that proof outputs and previous trusted state are consistent
    // if consistent, verify proof and create new trusted state
    // concatenate (length_prefix || previous_trusted_state || new_trusted_state) and commit
    // assert that the vk matches the one from trusted state
    let trusted_state = sp1_zkvm::io::read::<TrustedState>();
    let recursion_input = sp1_zkvm::io::read::<RecursionInput>();

    // deserialize the outputs
    let helios_outputs = ProofOutputs::abi_decode(&recursion_input.public_values).unwrap();

    let new_trusted_state = TrustedState {
        previous_header: helios_outputs.prevHeader.0,
        previous_head: helios_outputs.prevHead.try_into().unwrap(),
        previous_sync_committee_hash: helios_outputs.prevSyncCommitteeHash.0,
        new_head: helios_outputs.newHead.try_into().unwrap(),
        new_header: helios_outputs.newHeader.0,
        execution_state_root: helios_outputs.executionStateRoot.0,
        execution_block_number: helios_outputs.executionBlockNumber.try_into().unwrap(),
        sync_committee_hash: helios_outputs.syncCommitteeHash.0,
        next_sync_committee_hash: helios_outputs.nextSyncCommitteeHash.0,
        helios_vk: recursion_input.vk,
    };

    // assert that the active committee from previous trusted state is the same as the previous committee of the new trusted state
    assert_eq!(
        new_trusted_state.previous_sync_committee_hash,
        trusted_state.sync_committee_hash
    );
    // assert that the previous head of the new trusted state is the same as the new head of the previous trusted state
    assert_eq!(new_trusted_state.previous_head, trusted_state.new_head);
    // assert that the previous header of the new trusted state is the same as the new header of the previous trusted state
    assert_eq!(new_trusted_state.previous_header, trusted_state.new_header);
    // assert that the new execution block number and header are greater than the previous ones
    assert!(new_trusted_state.execution_block_number > trusted_state.execution_block_number);
    assert!(new_trusted_state.previous_head > trusted_state.new_head);
    // assert that the verifying key has not changed
    assert_eq!(new_trusted_state.helios_vk, trusted_state.helios_vk);

    // verify the Helios proof
    let digest = Sha256::digest(&recursion_input.public_values);
    sp1_zkvm::lib::verify::verify_sp1_proof(&recursion_input.vk, &digest.into());

    // commit the new outputs
    let trusted_state_bytes = bincode::serialize(&new_trusted_state).unwrap();
    let trusted_state_len = trusted_state_bytes.len() as u64;
    let new_trusted_state_bytes = bincode::serialize(&new_trusted_state).unwrap();
    let mut output = Vec::new();
    output.extend_from_slice(&trusted_state_len.to_le_bytes());
    output.extend_from_slice(&trusted_state_bytes);
    output.extend_from_slice(&new_trusted_state_bytes);
    sp1_zkvm::io::commit_slice(&output);
}
