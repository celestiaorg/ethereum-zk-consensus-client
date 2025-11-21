use alloy::sol_types::SolValue;
use celestia_grpc_client::CelestiaIsmClient;
use celestia_grpc_client::types::ClientConfig;
use sp1_sdk::{HashableKey, ProverClient, SP1Proof, SP1Stdin, include_elf};
use types::{MsgCreateStateTransitionVerifier, MsgUpdateStateTransitionVerifier};
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
        dotenvy::dotenv().ok();
        let mut active_trusted_state: Option<TrustedState> = None;
        let (_, helios_vk) = self.client.setup(LIGHTCLIENT_ELF);
        let (_, wrapper_vk) = self.client.setup(WRAPPER_ELF);
        let ism_client = CelestiaIsmClient::new(ClientConfig::from_env()?).await?;
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
                            creator: ism_client.signer_address().to_string(),
                            trusted_state: initial_trusted_state_bytes,
                            groth16_vkey: GROTH16_VK.to_vec(),
                            state_transition_vkey: wrapper_vk.vk.bytes32_raw().to_vec(),
                        };
                        let response = ism_client.send_tx(create_message).await?;
                        info!("Transaction submitted: {:?}", response);

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
                            signer: ism_client.signer_address().to_string(),
                        };

                        println!(
                            "Public values: {:?}, length: {}",
                            proof.public_values.to_vec(),
                            proof.public_values.to_vec().len()
                        );
                        let response = ism_client.send_tx(update_message).await?;
                        println!("Response: {:?}", response);
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
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to set default crypto provider");
    let operator = SP1HeliosOperator::new(CONSENSUS_RPC_URL.to_string(), CHAIN_ID).await;
    info!("Starting service...");
    operator.start_service().await.unwrap();
}

// address: celestia1d2qfkdk27r2x4y67ua5r2pj7ck5t8n4890x9wy
// address: celestia1y3kf30y9zprqzr2g2gjjkw3wls0a35pfs3a58q

// key: f7ec3cfaa1ae36c9c907d5ed5397503fc6e9f26cb69bfd83dbe45c5b2a717021
// key: 6e30efb1d3ebd30d1ba08c8d5fc9b190e08394009dc1dd787a69e60c33288a8c

//trusted_state: UAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
