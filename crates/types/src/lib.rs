use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MockTrustedState {
    pub previous_height: u64,
    pub previous_root: [u8; 32],
    pub new_height: u64,
    pub new_root: [u8; 32],
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TrustedState {
    pub execution_state_root: [u8; 32],
    pub execution_block_number: u64,
    pub new_header: [u8; 32],
    pub new_head: u64,
    pub sync_committee_hash: [u8; 32],
    pub previous_header: [u8; 32],
    pub previous_sync_committee_hash: [u8; 32],
    pub previous_head: u64,
    pub next_sync_committee_hash: [u8; 32],
    pub helios_vk: [u32; 8],
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RecursionInput {
    pub vk: [u32; 8],
    pub public_values: Vec<u8>,
}
