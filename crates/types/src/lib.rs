use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct CircuitInput {
    pub trusted_state: TrustedState,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TrustedState {
    pub previous_height: u64,
    pub previous_root: [u8; 32],
    pub new_height: u64,
    pub new_root: [u8; 32],
}
