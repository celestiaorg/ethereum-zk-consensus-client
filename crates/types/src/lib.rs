use prost::Name;
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
    pub previous_header: [u8; 32],
    pub previous_head: u64,
    pub previous_sync_committee_hash: [u8; 32],
    pub new_head: u64,
    pub new_header: [u8; 32],
    pub execution_state_root: [u8; 32],
    pub execution_block_number: u64,
    pub sync_committee_hash: [u8; 32],
    pub next_sync_committee_hash: [u8; 32],
    pub helios_vk: [u32; 8],
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RecursionInput {
    pub vk: [u32; 8],
    pub public_values: Vec<u8>,
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgCreateConsensusISM {
    /// creator is the message sender.
    #[prost(string, tag = "1")]
    pub creator: ::prost::alloc::string::String,
    /// the trusted state bytes
    #[prost(bytes = "vec", tag = "2")]
    pub trusted_state: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub groth16_vkey: ::prost::alloc::vec::Vec<u8>,
    /// hash-based commitment to the verifier key used for state transition
    #[prost(bytes = "vec", tag = "4")]
    pub state_transition_vkey: ::prost::alloc::vec::Vec<u8>,
}

impl Name for MsgCreateConsensusISM {
    const NAME: &'static str = "MsgCreateConsensusISM";
    const PACKAGE: &'static str = "celestia.zkism.v1";
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgCreateConsensusISMResponse {
    #[prost(bytes = "vec", tag = "1")]
    pub trusted_state: ::prost::alloc::vec::Vec<u8>,
}

/// MsgUpdateEvolveEvmISM  is the request type for UpdateEvolveEvmISM .
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgUpdateConsensusISM {
    /// ism identifier
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    /// proof is the ZK proof bytes (groth16).
    #[prost(bytes = "vec", tag = "2")]
    pub proof: ::prost::alloc::vec::Vec<u8>,
    /// the public values used for proof verification.
    #[prost(bytes = "vec", tag = "3")]
    pub public_values: ::prost::alloc::vec::Vec<u8>,
    /// the tx signer address
    #[prost(string, tag = "4")]
    pub signer: ::prost::alloc::string::String,
}

impl Name for MsgUpdateConsensusISM {
    const NAME: &'static str = "MsgUpdateConsensusISM";
    const PACKAGE: &'static str = "celestia.zkism.v1";
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgUpdateConsensusISMResponse {
    #[prost(bytes = "vec", tag = "1")]
    pub trusted_state: ::prost::alloc::vec::Vec<u8>,
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EventCreateStateTransitionVerifier {
    /// the owner or creator of the ism
    #[prost(string, tag = "1")]
    pub owner: ::prost::alloc::string::String,
    /// trusted state
    #[prost(bytes = "vec", tag = "2")]
    pub trusted_state: ::prost::alloc::vec::Vec<u8>,
    #[prost(string, tag = "3")]
    pub groth16_vkey: ::prost::alloc::string::String,
    /// hash-based commitment to the verifier key used for state transition
    /// (hex-encoded)
    #[prost(string, tag = "4")]
    pub state_transition_vkey: ::prost::alloc::string::String,
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EventUpdateStateTransitionVerifier {
    /// unique hyperlane identifier
    #[prost(bytes = "vec", tag = "1")]
    pub trusted_state: ::prost::alloc::vec::Vec<u8>,
}
