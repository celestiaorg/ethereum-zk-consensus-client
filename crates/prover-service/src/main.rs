use alloy::{
    hex::FromHex,
    providers::{Provider, ProviderBuilder},
    sol_types::SolValue,
};
use alloy_primitives::{Address, FixedBytes};
use celestia_grpc_client::{
    CelestiaIsmClient, proto::celestia::zkism::v1::MsgCreateInterchainSecurityModule,
    types::ClientConfig,
};
use celestia_grpc_client::{
    MsgSubmitMessages,
    proto::celestia::zkism::v1::{MsgUpdateInterchainSecurityModule, QueryIsmRequest},
};
use ev_zkevm_types::programs::hyperlane::types::{
    HYPERLANE_MERKLE_TREE_KEYS, HyperlaneBranchProof, HyperlaneBranchProofInputs,
    HyperlaneMessageInputs,
};
use reqwest::Url;
use sp1_sdk::{
    HashableKey, Prover, ProverClient, SP1Proof, SP1Stdin, include_elf, network::NetworkMode,
};
use tracing_subscriber::EnvFilter;
use types::{RecursionInput, TrustedState};
pub const WRAPPER_ELF: &[u8] = include_elf!("sp1-helios");
const GROTH16_VK: &[u8] = include_bytes!("../../../groth16_vk.bin");
use anyhow::Result;
use core::panic;
use helios_consensus_core::consensus_spec::MainnetConsensusSpec;
use helios_ethereum::{consensus::Inner, rpc::ConsensusRpc, rpc::http_rpc::HttpRpc};
use sp1_helios_primitives::types::{ProofInputs, ProofOutputs};
use sp1_helios_script::{get_client, get_updates};
use sp1_prover::components::CpuProverComponents;
use sp1_sdk::{SP1ProofWithPublicValues, SP1ProvingKey};
use std::{str::FromStr, sync::Arc, time::Instant};
use tracing::{debug, error, info};
use zkevm_storage::hyperlane::{
    StoredHyperlaneMessage, message::HyperlaneMessageStore, snapshot::HyperlaneSnapshotStore,
};
pub mod config;
mod hyperlane;
use config::ProverConfig;

pub type SP1Prover = dyn Prover<CpuProverComponents>;

const LIGHTCLIENT_ELF: &[u8] = include_bytes!("../../../elfs/helios");
pub const EV_HYPERLANE_ELF: &[u8] = include_elf!("ev-hyperlane-program");

pub struct SP1HeliosOperator {
    prover_client: Arc<SP1Prover>,
    lightclient_pk: Arc<SP1ProvingKey>,
    config: ProverConfig,
}

impl SP1HeliosOperator {
    /// Fetch values and generate an 'update' proof for the SP1 Helios contract.
    async fn request_update(
        &self,
        client: Inner<MainnetConsensusSpec, HttpRpc>,
        head: u64,
    ) -> Result<Option<SP1ProofWithPublicValues>> {
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
            let client = self.prover_client.clone();
            let pk = self.lightclient_pk.clone();

            move || client.prove(&pk, &stdin, sp1_sdk::SP1ProofMode::Compressed)
        })
        .await??;

        info!("Attempting to update to new head block: {:?}", latest_block);
        Ok(Some(proof))
    }

    /// Create a new SP1 Helios operator.
    pub async fn new(config: ProverConfig) -> Self {
        // read SP1_PROVER from env
        let sp1_prover = std::env::var("SP1_PROVER").unwrap_or("cpu".to_string());
        let prover_client: Arc<SP1Prover> = match sp1_prover.as_str() {
            "network" => Arc::new(
                ProverClient::builder()
                    .network_for(NetworkMode::Mainnet)
                    .rpc_url("https://rpc.mainnet.succinct.xyz")
                    .build(),
            ),
            "cpu" => Arc::new(ProverClient::builder().cpu().build()),
            _ => panic!(
                "Unsupported SP1_PROVER: {}, supported modes are network and cpu",
                sp1_prover
            ),
        };

        tracing::info!("Setting up light client program...");
        let (lightclient_pk, _) = prover_client.setup(LIGHTCLIENT_ELF);

        let this = Self {
            prover_client,
            lightclient_pk: Arc::new(lightclient_pk),
            config,
        };

        this
    }

    /// Run a single iteration of the operator, possibly posting a new update on chain.
    pub async fn run_once(&self) -> Result<()> {
        // Get the current slot from the contract
        let slot = self.config.trusted_head();

        // Fetch the checkpoint at that slot
        let client = get_client(
            Some(slot),
            self.config.consensus_rpc_url(),
            self.config.chain_id(),
        )
        .await?;

        assert_eq!(
            client.store.finalized_header.beacon().slot,
            slot,
            "Bootstrapped client has mismatched finalized slot, this is a bug!"
        );

        // Request an update
        match self
            .request_update(client, self.config.trusted_head())
            .await
        {
            Ok(Some(proof)) => {
                info!("Update proof: {:?}", proof);
            }
            Ok(None) => {
                info!("Contract is up to date");
            }
            Err(e) => {
                error!("Header range request failed: {}", e);
            }
        }

        Ok(())
    }

    pub async fn start_service(&self) -> Result<()> {
        let mut filter = EnvFilter::new(self.config.log_filter());
        if let Ok(env_filter) = std::env::var("RUST_LOG")
            && let Ok(parsed) = env_filter.parse()
        {
            filter = filter.add_directive(parsed);
        }
        tracing_subscriber::fmt().with_env_filter(filter).init();
        let (_, helios_vk) = self.prover_client.setup(LIGHTCLIENT_ELF);
        let (_, wrapper_vk) = self.prover_client.setup(WRAPPER_ELF);
        let prover_client = ProverClient::builder()
            .network_for(NetworkMode::Mainnet)
            .rpc_url("https://rpc.mainnet.succinct.xyz")
            .build();
        let (hyperlane_pk, hyperlane_vk) = prover_client.setup(EV_HYPERLANE_ELF);
        let ism_client = CelestiaIsmClient::new(ClientConfig::from_env()?).await?;

        info!("Starting service...");
        let mut active_trusted_state: Option<TrustedState> = None;
        let mut trusted_head: u64 = self.config.trusted_head();

        let verifier_response = ism_client
            .verifier(QueryIsmRequest {
                id: self.config.verifier_id().to_string(),
            })
            .await;

        if verifier_response.is_ok() {
            let ism = verifier_response.unwrap().ism.unwrap();
            active_trusted_state = Some(bincode::deserialize(&ism.state).unwrap());
        }

        let storage_path = dirs::home_dir()
            .expect("cannot find home directory")
            .join(".ev-prover")
            .join("data");

        let hyperlane_message_store =
            Arc::new(HyperlaneMessageStore::new(storage_path.clone()).unwrap());
        let snapshot_store = Arc::new(HyperlaneSnapshotStore::new(storage_path, None).unwrap());

        let evm_provider = ProviderBuilder::new()
            .connect_http(Url::parse("https://rpc.ankr.com/eth_sepolia/3021010a3fb9fc2c849dc6bd38774dbd248c4df99be6c8aa2d6841f308b95230").unwrap());

        let mut indexer_height = 9000000;
        let mut trusted_execution_block_number = 1;

        // if no trusted state, generate Helios proof, install Verifier
        // if trusted state, supply trusted state to wrapper, alongside new Helios proof
        // submit wrapped proof with outputs to Verifier => update state transition
        loop {
            if active_trusted_state.is_none() {
                let consensus_client = get_client(
                    Some(self.config.trusted_head()),
                    self.config.consensus_rpc_url(),
                    self.config.chain_id(),
                )
                .await?;
                assert_eq!(
                    consensus_client.store.finalized_header.beacon().slot,
                    self.config.trusted_head(),
                    "Bootstrapped client has mismatched finalized slot, this is a bug!"
                );
                match self.request_update(consensus_client, trusted_head).await {
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
                        let create_message = MsgCreateInterchainSecurityModule {
                            creator: ism_client.signer_address().to_string(),
                            state: initial_trusted_state_bytes,
                            groth16_vkey: GROTH16_VK.to_vec(),
                            state_transition_vkey: wrapper_vk.vk.bytes32_raw().to_vec(),
                            // todo: replace with actual state membership vkey
                            state_membership_vkey: hyperlane_vk.vk.bytes32_raw().to_vec(),
                        };
                        let response = ism_client.send_tx(create_message).await?;
                        if !response.success {
                            error!("Failed to create ISM: {:?}", response);
                            return Err(anyhow::anyhow!("Failed to create ISM"));
                        }
                        info!("Transaction submitted: {:?}", response);

                        // udpate trusted state
                        trusted_head = initial_trusted_state.new_head;
                        trusted_execution_block_number =
                            initial_trusted_state.execution_block_number;
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
                    self.config.consensus_rpc_url(),
                    self.config.chain_id(),
                )
                .await?;
                assert_eq!(
                    consensus_client.store.finalized_header.beacon().slot,
                    trusted_state.new_head,
                    "Bootstrapped client has mismatched finalized slot, this is a bug!"
                );
                match self.request_update(consensus_client, trusted_head).await {
                    Ok(Some(proof)) => {
                        info!("Wrapping proof to compute Update");
                        let (pk, _) = self.prover_client.setup(WRAPPER_ELF);
                        let mut stdin = SP1Stdin::new();
                        // write trusted state
                        stdin.write(&trusted_state);
                        let recursion_input = RecursionInput {
                            vk: helios_vk.vk.hash_u32(),
                            public_values: proof.public_values.to_vec(),
                        };
                        stdin.write(&recursion_input);
                        let SP1Proof::Compressed(ref proof) = proof.proof else {
                            panic!()
                        };
                        stdin.write_proof(*proof.clone(), helios_vk.vk.clone());
                        // generate the wrapped proof
                        let start_time = Instant::now();
                        let proof = self.prover_client.prove(
                            &pk,
                            &stdin,
                            sp1_sdk::SP1ProofMode::Groth16,
                        )?;
                        info!("Elapsed: {:?}", start_time.elapsed().as_millis());
                        let update_message = MsgUpdateInterchainSecurityModule {
                            id: self.config.verifier_id().to_string(),
                            proof: proof.bytes(),
                            public_values: proof.public_values.to_vec(),
                            signer: ism_client.signer_address().to_string(),
                        };

                        let response = ism_client.send_tx(update_message).await?;
                        debug!("Response: {:?}", response);
                        if !response.success {
                            error!("Failed to update ISM: {:?}", response);
                            return Err(anyhow::anyhow!("Failed to update ISM"));
                        }

                        let verifier_response = ism_client
                            .verifier(QueryIsmRequest {
                                id: self.config.verifier_id().to_string(),
                            })
                            .await
                            .unwrap();

                        let ism = verifier_response.ism.unwrap();
                        let trusted_state: TrustedState = bincode::deserialize(&ism.state).unwrap();
                        debug!("Verifier Trusted State: {:?}", trusted_state);

                        trusted_head = trusted_state.new_head;
                        trusted_execution_block_number = trusted_state.execution_block_number;
                        active_trusted_state = Some(trusted_state);
                    }
                    Ok(None) => {
                        info!("Verifier is up to date!");
                    }
                    Err(e) => {
                        error!("Header range request failed: {}", e);
                    }
                }
            }
            // generate hyperlane message proof for range previous_trusted_height+1..=new_trusted_height
            // and submit it to the ISM
            info!(
                "Indexing messages from height {} to {}",
                indexer_height, trusted_head
            );

            hyperlane::index_sepolia(
                indexer_height,
                trusted_execution_block_number,
                hyperlane_message_store.clone(),
                evm_provider.clone().into(),
            )
            .await?;

            // prove and submit indexed messages
            let mut messages: Vec<StoredHyperlaneMessage> = Vec::new();
            for block in indexer_height..=trusted_execution_block_number {
                messages.extend(hyperlane_message_store.get_by_block(block)?);
            }

            if messages.is_empty() {
                info!("No new messages found");
                continue;
            }

            let keys: Vec<FixedBytes<32>> = HYPERLANE_MERKLE_TREE_KEYS
                .iter()
                .map(|k| {
                    FixedBytes::from_hex(k)
                        .map_err(|e| anyhow::anyhow!("Failed to parse fixed bytes: {e}"))
                })
                .collect::<Result<Vec<_>>>()?;

            let merkle_proof = evm_provider
                .get_proof(
                    Address::from_str("0xA82571C75164B76721C4047182b73014072E3D9B")?,
                    keys,
                )
                .block_id(trusted_execution_block_number.into())
                .await?;

            let branch_proof = HyperlaneBranchProof::new(merkle_proof);

            let snapshot = snapshot_store
                .get_snapshot(snapshot_store.current_index()?)
                .unwrap();

            // Construct program inputs from values
            let input = HyperlaneMessageInputs::new(
                hex::encode(active_trusted_state.clone().unwrap().execution_state_root),
                Address::from_str("0xA82571C75164B76721C4047182b73014072E3D9B")
                    .unwrap()
                    .to_string(),
                messages.clone().into_iter().map(|m| m.message).collect(),
                HyperlaneBranchProofInputs::from(branch_proof),
                snapshot.tree.clone(),
            );

            let mut stdin = SP1Stdin::new();
            stdin.write(&input);
            let proof = prover_client.prove(&hyperlane_pk, &stdin).groth16().run()?;

            // submit proof to ZKISM verifier
            // Prepare the proof submission message
            let message_proof_msg = MsgSubmitMessages::new(
                "0x726f757465725f69736d000000000000000000000000002a0000000000000000".to_string(),
                trusted_head,
                proof.bytes(),
                proof.public_values.to_vec(),
                ism_client.signer_address().to_string(),
            );

            // Submit the proof to ZKISM
            info!("Submitting Hyperlane tree proof to ZKISM...");
            let response = ism_client.send_tx(message_proof_msg).await?;
            if !response.success {
                error!(
                    "Failed to submit Hyperlane tree proof to ZKISM: {:?}",
                    response
                );
                return Err(anyhow::anyhow!(
                    "Failed to submit Hyperlane tree proof to ZKISM"
                ));
            }

            // update snapshot
            let mut new_snapshot = snapshot.clone();
            for message in messages.clone() {
                new_snapshot.tree.insert(message.message.id())?;
            }
            snapshot_store.insert_snapshot(snapshot_store.current_index()? + 1, new_snapshot)?;
            indexer_height = trusted_head + 1;
        }
    }
}

#[tokio::main]
async fn main() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to set default crypto provider");

    dotenvy::dotenv().ok();
    let config = ProverConfig::from_env().unwrap();
    let operator = SP1HeliosOperator::new(config).await;
    info!("Starting service...");
    operator.start_service().await.unwrap();
}

// address: celestia1d2qfkdk27r2x4y67ua5r2pj7ck5t8n4890x9wy
// address: celestia1y3kf30y9zprqzr2g2gjjkw3wls0a35pfs3a58q

// key: f7ec3cfaa1ae36c9c907d5ed5397503fc6e9f26cb69bfd83dbe45c5b2a717021
// key: 6e30efb1d3ebd30d1ba08c8d5fc9b190e08394009dc1dd787a69e60c33288a8c

//trusted_state: UAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
