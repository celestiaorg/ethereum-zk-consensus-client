use prost::Name;

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgCreateStateTransitionVerifier {
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

impl Name for MsgCreateStateTransitionVerifier {
    const NAME: &'static str = "MsgCreateStateTransitionVerifier";
    const PACKAGE: &'static str = "celestia.zkism.v1";
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgCreateStateTransitionVerifierResponse {
    #[prost(bytes = "vec", tag = "1")]
    pub trusted_state: ::prost::alloc::vec::Vec<u8>,
}

/// MsgUpdateZKExecutionISM is the request type for UpdateZKExecutionISM.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgUpdateStateTransitionVerifier {
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

impl Name for MsgUpdateStateTransitionVerifier {
    const NAME: &'static str = "MsgUpdateStateTransitionVerifier";
    const PACKAGE: &'static str = "celestia.zkism.v1";
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgUpdateStateTransitionVerifierResponse {
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

