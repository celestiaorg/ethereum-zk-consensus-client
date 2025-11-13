use celestia_grpc::{GrpcClient, TxConfig};
use prost::Name;
use sp1_sdk::{HashableKey, ProverClient, SP1Stdin, include_elf};
use types::TrustedState;
pub const PROGRAM_ELF: &[u8] = include_elf!("circuit");
const GROTH16_VK: &[u8] = include_bytes!("../../../groth16_vk.bin");

#[tokio::main]
async fn main() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .unwrap();

    let initial_trusted_state = TrustedState {
        previous_height: 0,
        previous_root: [0; 32],
        new_height: 0,
        new_root: [0; 32],
    };

    let initial_trusted_state_bytes = bincode::serialize(&initial_trusted_state).unwrap();

    let prover_client = ProverClient::from_env();
    let (pk, vk) = prover_client.setup(PROGRAM_ELF);

    let client = GrpcClient::builder()
        .private_key_hex("f7ec3cfaa1ae36c9c907d5ed5397503fc6e9f26cb69bfd83dbe45c5b2a717021")
        .url("http://localhost:9090")
        .build()
        .unwrap();
    let cfg = TxConfig {
        gas_limit: Some(1000000),
        gas_price: Some(1000.0),
        memo: None,
        priority: celestia_grpc::grpc::TxPriority::High,
    };
    // create verifier module from trusted state
    let create_message = MsgCreateStateTransitionVerifier {
        creator: "celestia1d2qfkdk27r2x4y67ua5r2pj7ck5t8n4890x9wy".to_string(),
        trusted_state: initial_trusted_state_bytes,
        groth16_vkey: GROTH16_VK.to_vec(),
        state_transition_vkey: vk.bytes32_raw().to_vec(),
    };
    let response = client.submit_message(create_message, cfg.clone());
    let out = response.await.unwrap();
    println!("Response: {:?}", out);
    // submit proof to update verifier module

    let mut stdin = SP1Stdin::new();
    stdin.write(&initial_trusted_state);
    let proof = prover_client.prove(&pk, &stdin).groth16().run().unwrap();

    let update_message = MsgUpdateStateTransitionVerifier {
        id: "0x726f757465725f69736d000000000000000000000000002a0000000000000000".to_string(),
        proof: proof.bytes(),
        public_values: proof.public_values.to_vec(),
        signer: "celestia1d2qfkdk27r2x4y67ua5r2pj7ck5t8n4890x9wy".to_string(),
    };

    println!(
        "Public values: {:?}, length: {}",
        proof.public_values.to_vec(),
        proof.public_values.to_vec().len()
    );
    let response = client.submit_message(update_message, cfg);
    let out = response.await.unwrap();
    println!("Response: {:?}", out);
}

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

// address: celestia1d2qfkdk27r2x4y67ua5r2pj7ck5t8n4890x9wy
// address: celestia1y3kf30y9zprqzr2g2gjjkw3wls0a35pfs3a58q

// key: f7ec3cfaa1ae36c9c907d5ed5397503fc6e9f26cb69bfd83dbe45c5b2a717021
// key: 6e30efb1d3ebd30d1ba08c8d5fc9b190e08394009dc1dd787a69e60c33288a8c

//trusted_state: UAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
