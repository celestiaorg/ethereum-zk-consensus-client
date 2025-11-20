#![no_main]

use types::CircuitInput;

sp1_zkvm::entrypoint!(main);

pub fn main() {
    // take proof and previous trusted state
    // assert that proof outputs and previous trusted state are consistent
    // if consistent, verify proof and create new trusted state
    // concatenate (length_prefix || previous_trusted_state || new_trusted_state) and commit
}
