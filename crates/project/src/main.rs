use alloy::sol_types::SolValue;
use celestia_grpc::{GrpcClient, TxConfig};
use prost::Name;
use sp1_sdk::{HashableKey, ProverClient, SP1Proof, SP1Stdin, include_elf};
use types::{RecursionInput, TrustedState};
pub const WRAPPER_ELF: &[u8] = include_elf!("circuit");
const GROTH16_VK: &[u8] = include_bytes!("../../../groth16_vk.bin");

use anyhow::Result;
use helios_consensus_core::consensus_spec::MainnetConsensusSpec;
use helios_ethereum::consensus::Inner;
use helios_ethereum::rpc::ConsensusRpc;
use helios_ethereum::rpc::http_rpc::HttpRpc;
use sp1_helios_primitives::types::{ProofInputs, ProofOutputs};
use sp1_helios_script::{get_client, get_updates};
use sp1_sdk::{EnvProver, SP1ProofWithPublicValues, SP1ProvingKey};
use std::sync::Arc;
use tracing::{error, info};

const TRUSTED_HEAD: u64 = 280984 * 32 - 64;
const LIGHTCLIENT_ELF: &[u8] = include_bytes!("../../../elfs/helios");
const CONSENSUS_RPC_URL: &str = "https://ethereum-sepolia-beacon-api.publicnode.com";
const CHAIN_ID: u64 = 11155111;

pub struct SP1HeliosOperator {
    client: Arc<EnvProver>,
    lightclient_pk: Arc<SP1ProvingKey>,
    chain_id: u64,
    consensus_rpc: String,
}

impl SP1HeliosOperator {
    /// Fetch values and generate an 'update' proof for the SP1 Helios contract.
    async fn request_update(
        &self,
        client: Inner<MainnetConsensusSpec, HttpRpc>,
    ) -> Result<Option<SP1ProofWithPublicValues>> {
        let head: u64 = TRUSTED_HEAD;

        let mut stdin = SP1Stdin::new();

        // Setup client.
        let updates = get_updates(&client).await;
        let finality_update = client.rpc.get_finality_update().await.unwrap();

        // Check if contract is up to date
        let latest_block = finality_update.finalized_header().beacon().slot;
        if latest_block <= head {
            info!("Contract is up to date. Nothing to update.");
            return Ok(None);
        } else if !latest_block.is_multiple_of(32) {
            info!("Attempted to commit to a non-checkpoint slot: {latest_block}. Skipping update.");
            return Ok(None);
        }

        info!(
            "Updating to new head block: {:?} from {:?}",
            latest_block, head
        );

        // Fetch the contract storage, if any.
        let contract_storage = Vec::new();
        // Create program inputs
        let expected_current_slot = client.expected_current_slot();
        let inputs = ProofInputs {
            updates,
            finality_update,
            expected_current_slot,
            store: client.store.clone(),
            genesis_root: client.config.chain.genesis_root,
            forks: client.config.forks.clone(),
            contract_storage,
        };
        let encoded_proof_inputs = serde_cbor::to_vec(&inputs)?;
        stdin.write_slice(&encoded_proof_inputs);

        // Generate proof.
        let proof = tokio::task::spawn_blocking({
            let client = self.client.clone();
            let pk = self.lightclient_pk.clone();

            move || client.prove(&pk, &stdin).compressed().run()
        })
        .await??;

        info!("Attempting to update to new head block: {:?}", latest_block);
        Ok(Some(proof))
    }

    /// Create a new SP1 Helios operator.
    pub async fn new(consensus_rpc: String, chain_id: u64) -> Self {
        let client = ProverClient::from_env();

        tracing::info!("Setting up light client program...");
        let (lightclient_pk, _) = client.setup(LIGHTCLIENT_ELF);

        let this = Self {
            client: Arc::new(client),
            lightclient_pk: Arc::new(lightclient_pk),
            chain_id: chain_id,
            consensus_rpc: consensus_rpc,
        };

        this
    }

    /// Run a single iteration of the operator, possibly posting a new update on chain.
    pub async fn run_once(&self) -> Result<()> {
        // Get the current slot from the contract
        let slot = TRUSTED_HEAD;

        // Fetch the checkpoint at that slot
        let client = get_client(Some(slot), &self.consensus_rpc, self.chain_id).await?;

        assert_eq!(
            client.store.finalized_header.beacon().slot,
            slot,
            "Bootstrapped client has mismatched finalized slot, this is a bug!"
        );

        // Request an update
        match self.request_update(client).await {
            Ok(Some(proof)) => {
                info!("Update proof: {:?}", proof);
            }
            Ok(None) => {
                // Contract is up to date. Nothing to update.
            }
            Err(e) => {
                error!("Header range request failed: {}", e);
            }
        }

        Ok(())
    }

    pub async fn start_service(&self) -> Result<()> {
        let mut active_trusted_state: Option<TrustedState> = None;
        let (_, helios_vk) = self.client.setup(LIGHTCLIENT_ELF);
        let (_, wrapper_vk) = self.client.setup(WRAPPER_ELF);
        let grpc_client = GrpcClient::builder()
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
        // if no trusted state, generate Helios proof, install Verifier
        // if trusted state, supply trusted state to wrapper, alongside new Helios proof
        // submit wrapped proof with outputs to Verifier => update state transition
        loop {
            if active_trusted_state.is_none() {
                let consensus_client =
                    get_client(Some(TRUSTED_HEAD), &self.consensus_rpc, self.chain_id).await?;
                assert_eq!(
                    consensus_client.store.finalized_header.beacon().slot,
                    TRUSTED_HEAD,
                    "Bootstrapped client has mismatched finalized slot, this is a bug!"
                );
                match self.request_update(consensus_client).await {
                    Ok(Some(proof)) => {
                        let outputs =
                            ProofOutputs::abi_decode(proof.public_values.as_slice()).unwrap();
                        info!("Installing ISM from Proof outputs");
                        let initial_trusted_state = TrustedState {
                            previous_header: outputs.prevHeader.0,
                            previous_head: outputs.prevHead.try_into().unwrap(),
                            previous_sync_committee_hash: outputs.prevSyncCommitteeHash.0,
                            new_head: outputs.newHead.try_into().unwrap(),
                            new_header: outputs.newHeader.0,
                            execution_state_root: outputs.executionStateRoot.0,
                            execution_block_number: outputs
                                .executionBlockNumber
                                .try_into()
                                .unwrap(),
                            sync_committee_hash: outputs.syncCommitteeHash.0,
                            next_sync_committee_hash: outputs.nextSyncCommitteeHash.0,
                            helios_vk: helios_vk.vk.hash_u32(),
                        };
                        let initial_trusted_state_bytes =
                            bincode::serialize(&initial_trusted_state).unwrap();
                        let create_message = MsgCreateStateTransitionVerifier {
                            creator: "celestia1d2qfkdk27r2x4y67ua5r2pj7ck5t8n4890x9wy".to_string(),
                            trusted_state: initial_trusted_state_bytes,
                            groth16_vkey: GROTH16_VK.to_vec(),
                            state_transition_vkey: wrapper_vk.vk.bytes32_raw().to_vec(),
                        };
                        let response = grpc_client.submit_message(create_message, cfg.clone());
                        let out = response.await.unwrap();
                        info!("Transaction submitted: {:?}", out);

                        // udpate trusted state
                        active_trusted_state = Some(initial_trusted_state);
                    }
                    Ok(None) => {
                        error!("No proof was generated, this is a bug!");
                    }
                    Err(e) => {
                        error!("Header range request failed: {}", e);
                    }
                }
            } else {
                let trusted_state = active_trusted_state.clone().unwrap();
                let consensus_client = get_client(
                    Some(trusted_state.new_head),
                    &self.consensus_rpc,
                    self.chain_id,
                )
                .await?;
                assert_eq!(
                    consensus_client.store.finalized_header.beacon().slot,
                    trusted_state.new_head,
                    "Bootstrapped client has mismatched finalized slot, this is a bug!"
                );
                match self.request_update(consensus_client).await {
                    Ok(Some(proof)) => {
                        info!("Wrapping proof to compute Update");
                        let (pk, vk) = self.client.setup(WRAPPER_ELF);
                        let mut stdin = SP1Stdin::new();
                        // write trusted state
                        stdin.write(&trusted_state);
                        let recursion_input = RecursionInput {
                            vk: vk.vk.hash_u32(),
                            public_values: proof.public_values.to_vec(),
                        };
                        stdin.write(&recursion_input);
                        let SP1Proof::Compressed(ref proof) = proof.proof else {
                            panic!()
                        };
                        stdin.write_proof(*proof.clone(), vk.vk.clone());
                        // generate the wrapped proof
                        let proof = self.client.prove(&pk, &stdin).groth16().run()?;
                        let update_message = MsgUpdateStateTransitionVerifier {
                            id:
                                "0x726f757465725f69736d000000000000000000000000002a0000000000000000"
                                    .to_string(),
                            proof: proof.bytes(),
                            public_values: proof.public_values.to_vec(),
                            signer: "celestia1d2qfkdk27r2x4y67ua5r2pj7ck5t8n4890x9wy".to_string(),
                        };

                        println!(
                            "Public values: {:?}, length: {}",
                            proof.public_values.to_vec(),
                            proof.public_values.to_vec().len()
                        );
                        let response = grpc_client.submit_message(update_message, cfg.clone());
                        let out = response.await.unwrap();
                        println!("Response: {:?}", out);
                    }
                    Ok(None) => {
                        error!("No proof was generated, this is a bug!");
                    }
                    Err(e) => {
                        error!("Header range request failed: {}", e);
                    }
                }
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let client = get_client(Some(TRUSTED_HEAD), CONSENSUS_RPC_URL, CHAIN_ID)
        .await
        .unwrap();
    let operator = SP1HeliosOperator::new(CONSENSUS_RPC_URL.to_string(), CHAIN_ID).await;
    let proof = operator.request_update(client).await.unwrap().unwrap();
    let outputs = ProofOutputs::abi_decode(proof.public_values.as_slice()).unwrap();
    println!(
        "New State Root: {:?}, New Height: {:?}",
        outputs.executionStateRoot, outputs.executionBlockNumber
    );
}

/*#[tokio::main]
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
}*/

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
