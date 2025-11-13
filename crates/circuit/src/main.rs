#![no_main]

use types::CircuitInput;

sp1_zkvm::entrypoint!(main);

pub fn main() {
    let input: CircuitInput = sp1_zkvm::io::read::<CircuitInput>();
    // in a real application: verify other inputs against trusted state form input
    let mut new_trusted_state = input.trusted_state.clone();
    new_trusted_state.new_root = [1; 32];
    new_trusted_state.new_height = new_trusted_state.previous_height + 1;

    let trusted_state_serialized = bincode::serialize(&input.trusted_state).unwrap();
    let new_trusted_state_serialized = bincode::serialize(&new_trusted_state).unwrap();
    let mut state: Vec<u8> = Vec::new();
    let trusted_state_len = trusted_state_serialized.len() as u64;
    state.extend_from_slice(&trusted_state_len.to_le_bytes());
    state.extend_from_slice(&trusted_state_serialized);
    state.extend_from_slice(&new_trusted_state_serialized);

    sp1_zkvm::io::commit_slice(&state);
}
