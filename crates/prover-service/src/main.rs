use alloy::{
    hex::FromHex,
    providers::{Provider, ProviderBuilder},
    sol_types::SolValue,
};
use alloy_primitives::{Address, FixedBytes};
use anyhow::Result;
use celestia_grpc_client::{
    CelestiaIsmClient, MsgCreateSyntheticTokenResponse, MsgProcessMessage, MsgSubmitMessages,
    MsgSubmitMessagesResponse,
    proto::{
        celestia::zkism::v1::{
            MsgCreateInterchainSecurityModule, MsgCreateInterchainSecurityModuleResponse,
            MsgCreateNoopHook, MsgCreateNoopHookResponse, MsgUpdateInterchainSecurityModule,
            MsgUpdateInterchainSecurityModuleResponse, QueryIsmRequest,
        },
        hyperlane::{
            core::v1::{MsgCreateMailbox, MsgCreateMailboxResponse},
            warp::v1::{MsgCreateSyntheticToken, MsgEnrollRemoteRouter, MsgSetToken, RemoteRouter},
        },
    },
    types::ClientConfig,
};
use core::panic;
use ev_zkevm_types::{
    hyperlane::encode_hyperlane_message,
    programs::hyperlane::types::{
        HYPERLANE_MERKLE_TREE_KEYS, HyperlaneBranchProof, HyperlaneBranchProofInputs,
        HyperlaneMessageInputs,
    },
};
use helios_consensus_core::consensus_spec::MainnetConsensusSpec;
use helios_ethereum::{consensus::Inner, rpc::ConsensusRpc, rpc::http_rpc::HttpRpc};
use sp1_helios_primitives::types::{ProofInputs, ProofOutputs};
use sp1_helios_script::{get_client, get_updates};
use sp1_prover::components::CpuProverComponents;
use sp1_sdk::{
    HashableKey, Prover, ProverClient, SP1Proof, SP1ProofWithPublicValues, SP1ProvingKey, SP1Stdin,
    include_elf, network::NetworkMode,
};
use std::{
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};
use tracing::{debug, error, info};
use tracing_subscriber::EnvFilter;
use types::{RecursionInput, TrustedState};
use zkevm_storage::hyperlane::{
    StoredHyperlaneMessage, message::HyperlaneMessageStore, snapshot::HyperlaneSnapshotStore,
};

pub mod config;
mod hyperlane;

use config::ProverConfig;

pub const WRAPPER_ELF: &[u8] = include_elf!("sp1-helios");
const GROTH16_VK: &[u8] = include_bytes!("../../../groth16_vk.bin");
const LIGHTCLIENT_ELF: &[u8] = include_bytes!("../../../elfs/helios");
pub const EV_HYPERLANE_ELF: &[u8] = include_elf!("ev-hyperlane-program");

const DEFAULT_TIMEOUT: u64 = 600;

pub type SP1Prover = dyn Prover<CpuProverComponents>;

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
        let latest_block = latest_block - (latest_block % 32);
        if latest_block <= head {
            info!("Contract is up to date. Nothing to update.");
            tokio::time::sleep(Duration::from_secs(10)).await;
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

        Self {
            prover_client,
            lightclient_pk: Arc::new(lightclient_pk),
            config,
        }
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

    pub async fn run(&self) -> Result<()> {
        let mut filter = EnvFilter::new(self.config.log_filter());
        if let Ok(env_filter) = std::env::var("RUST_LOG")
            && let Ok(parsed) = env_filter.parse()
        {
            filter = filter.add_directive(parsed);
        }
        tracing_subscriber::fmt().with_env_filter(filter).init();

        let (_, helios_vk) = self.prover_client.setup(LIGHTCLIENT_ELF);
        let (_, wrapper_vk) = self.prover_client.setup(WRAPPER_ELF);
        let (hyperlane_pk, hyperlane_vk) = self.prover_client.setup(EV_HYPERLANE_ELF);
        let ism_client = Arc::new(CelestiaIsmClient::new(ClientConfig::from_env()?).await?);

        info!("Starting service...");
        let mut active_trusted_state: Option<TrustedState> = None;
        let mut trusted_head: u64 = self.config.trusted_head();

        let verifier_response = ism_client
            .verifier(QueryIsmRequest {
                id: ism_client.ism_id().to_string(),
            })
            .await;

        if let Ok(verifier_response) = verifier_response {
            let ism = verifier_response.ism.unwrap();
            active_trusted_state = Some(bincode::deserialize(&ism.state).unwrap());
        }

        let storage_path = dirs::home_dir()
            .expect("cannot find home directory")
            .join(".hyp-zk-client")
            .join("data");

        let hyperlane_message_store =
            Arc::new(HyperlaneMessageStore::new(storage_path.clone()).unwrap());
        let snapshot_store = Arc::new(HyperlaneSnapshotStore::new(storage_path, None)?);

        let evm_provider = ProviderBuilder::new().connect_http(self.config.evm_rpc_url.parse()?);

        let mut indexer_height = 9000000;
        let mut trusted_execution_block_number = 1;

        /////////////////////
        //// Prover Loop ////
        /////////////////////
        loop {
            // If this is the first proof, deploy the ISM
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
                            merkle_tree_address: Address::from_str(
                                &self.config.merkle_tree_address,
                            )
                            .unwrap()
                            .into_word()
                            .to_vec(),
                            state_transition_vkey: wrapper_vk.vk.bytes32_raw().to_vec(),
                            // todo: replace with actual state membership vkey
                            state_membership_vkey: hyperlane_vk.vk.bytes32_raw().to_vec(),
                        };
                        let response = ism_client
                            .send_tx_typed::<_, MsgCreateInterchainSecurityModuleResponse>(
                                create_message,
                            )
                            .await?;
                        if !response.tx.success {
                            error!("Failed to create ISM: {:?}", response);
                            return Err(anyhow::anyhow!("Failed to create ISM"));
                        }
                        info!("Created ISM with id: {:?}", response.response.id);

                        // initialize hyperlane contracts
                        self.hyperlane_init(ism_client.clone()).await?;

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
            // If this is not the first proof, update the ISM
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
                            id: ism_client.ism_id().to_string(),
                            proof: proof.bytes(),
                            public_values: proof.public_values.to_vec(),
                            signer: ism_client.signer_address().to_string(),
                        };

                        let response = ism_client
                            .send_tx_typed::<_, MsgUpdateInterchainSecurityModuleResponse>(
                                update_message,
                            )
                            .await?;
                        debug!("Response: {:?}", response);
                        if !response.tx.success {
                            error!("Failed to update ISM: {:?}", response);
                            return Err(anyhow::anyhow!("Failed to update ISM"));
                        }

                        let verifier_response = ism_client
                            .verifier(QueryIsmRequest {
                                id: ism_client.ism_id().to_string(),
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
                indexer_height, trusted_execution_block_number
            );

            hyperlane::index_sepolia(
                indexer_height,
                trusted_execution_block_number,
                Address::from_str(&self.config.mailbox_address)?,
                hyperlane_message_store.clone(),
                evm_provider.clone(),
            )
            .await?;

            // prove and submit indexed messages
            let mut messages: Vec<StoredHyperlaneMessage> = Vec::new();
            for block in indexer_height..=trusted_execution_block_number {
                messages.extend(hyperlane_message_store.get_by_block(block)?);
            }

            if messages.is_empty() {
                info!("No new messages found");
                // sleep for 10 minutes
                tokio::time::sleep(Duration::from_secs(DEFAULT_TIMEOUT)).await;
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
                .get_proof(Address::from_str(&self.config.merkle_tree_address)?, keys)
                .block_id(trusted_execution_block_number.into())
                .await?;

            let branch_proof = HyperlaneBranchProof::new(merkle_proof);

            let snapshot = snapshot_store
                .get_snapshot(snapshot_store.current_index()?)
                .unwrap();

            // Construct program inputs from values
            let input = HyperlaneMessageInputs::new(
                hex::encode(active_trusted_state.clone().unwrap().execution_state_root),
                Address::from_str(&self.config.merkle_tree_address)
                    .unwrap()
                    .to_string(),
                messages.clone().into_iter().map(|m| m.message).collect(),
                HyperlaneBranchProofInputs::from(branch_proof),
                snapshot.tree.clone(),
            );

            let mut stdin = SP1Stdin::new();
            stdin.write(&input);
            let proof =
                self.prover_client
                    .prove(&hyperlane_pk, &stdin, sp1_sdk::SP1ProofMode::Groth16)?;

            // submit proof to ZKISM verifier
            // Prepare the proof submission message
            let message_proof_msg = MsgSubmitMessages::new(
                ism_client.ism_id().to_string(),
                proof.bytes(),
                proof.public_values.to_vec(),
                ism_client.signer_address().to_string(),
            );

            // Submit the proof to ZKISM
            info!("Submitting Hyperlane tree proof to ZKISM...");
            let response = ism_client
                .send_tx_typed::<_, MsgSubmitMessagesResponse>(message_proof_msg)
                .await?;
            if !response.tx.success {
                error!(
                    "Failed to submit Hyperlane tree proof to ZKISM: {:?}",
                    response
                );
                return Err(anyhow::anyhow!(
                    "Failed to submit Hyperlane tree proof to ZKISM"
                ));
            }
            println!("Verified messages: {:?}", response.response.messages);

            // update snapshot
            let mut new_snapshot = snapshot.clone();
            for message in messages.clone() {
                new_snapshot.tree.insert(message.message.id())?;
            }
            snapshot_store.insert_snapshot(snapshot_store.current_index()? + 1, new_snapshot)?;
            indexer_height = trusted_execution_block_number + 1;

            // relay messages to hyperlane remote router
            for message in messages.clone() {
                // skip messages that are not destined for the ISM
                if message.message.destination != 69420 {
                    continue;
                }
                println!("Relaying message: {:?}", message.message);
                let message_hex = alloy::hex::encode(encode_hyperlane_message(&message.message)?);
                let msg = MsgProcessMessage::new(
                    // mailbox id on Celestia
                    "0x68797065726c616e650000000000000000000000000000000000000000000000"
                        .to_string(),
                    ism_client.signer_address().to_string(),
                    // empty metadata; messages are pre-authorized before submission
                    alloy::hex::encode(vec![]),
                    message_hex,
                );

                let response = ism_client.send_tx(msg).await?;
                if !response.success {
                    error!(
                        "Failed to relay Hyperlane message to Celestia: {:?}",
                        response
                    );
                    continue;
                }

                info!(
                    "Successfully submitted Hyperlane message with id {} to Celestia",
                    message.message.id()
                );
            }
            // sleep for 10 minutes
            tokio::time::sleep(Duration::from_secs(DEFAULT_TIMEOUT)).await;
        }
    }

    async fn hyperlane_init(&self, ism_client: Arc<CelestiaIsmClient>) -> Result<()> {
        // first step: create the mailbox
        // second step: deploy the warp token
        // third step: set the ISM on the warp token
        // fourth step: enroll the remote router

        let create_noop_hook_message = MsgCreateNoopHook {
            owner: ism_client.signer_address().to_string(),
        };

        let create_noop_hook_response = ism_client
            .send_tx_typed::<_, MsgCreateNoopHookResponse>(create_noop_hook_message)
            .await?;

        if !create_noop_hook_response.tx.success {
            error!(
                "Failed to create noop hook: {:?}",
                create_noop_hook_response
            );
            return Err(anyhow::anyhow!("Failed to create noop hook"));
        }

        info!(
            "Created noop hook with id: {:?}",
            create_noop_hook_response.response.id
        );

        let mailbox_create_message = MsgCreateMailbox {
            owner: ism_client.signer_address().to_string(),
            local_domain: 69420,
            default_ism: ism_client.ism_id().to_string(),
            default_hook: create_noop_hook_response.response.id.clone(),
            required_hook: create_noop_hook_response.response.id,
        };

        let resp = ism_client
            .send_tx_typed::<_, MsgCreateMailboxResponse>(mailbox_create_message)
            .await?;

        if !resp.tx.success {
            error!("Failed to create mailbox: {:?}", resp);
            return Err(anyhow::anyhow!("Failed to create mailbox"));
        }

        let synthetic_token_create_message = MsgCreateSyntheticToken {
            owner: ism_client.signer_address().to_string(),
            origin_mailbox: resp.response.id,
        };

        let synthetic_token_response = ism_client
            .send_tx_typed::<_, MsgCreateSyntheticTokenResponse>(synthetic_token_create_message)
            .await?;
        if !synthetic_token_response.tx.success {
            error!(
                "Failed to create synthetic token: {:?}",
                synthetic_token_response.tx
            );
            return Err(anyhow::anyhow!("Failed to create synthetic token"));
        }

        let synthetic_token_id = synthetic_token_response.response.id;

        let set_synthetic_token_ism_message = MsgSetToken {
            owner: ism_client.signer_address().to_string(),
            token_id: synthetic_token_id.clone(),
            new_owner: ism_client.signer_address().to_string(),
            ism_id: ism_client.ism_id().to_string(),
            renounce_ownership: false,
        };

        let set_synthetic_token_ism_response =
            ism_client.send_tx(set_synthetic_token_ism_message).await?;
        if !set_synthetic_token_ism_response.success {
            error!(
                "Failed to set synthetic token ISM: {:?}",
                set_synthetic_token_ism_response
            );
            return Err(anyhow::anyhow!("Failed to set synthetic token ISM"));
        }

        info!("Created synthetic token with id: {}", &synthetic_token_id);

        let remote_router_enroll_message = MsgEnrollRemoteRouter {
            owner: ism_client.signer_address().to_string(),
            token_id: synthetic_token_id.clone(),
            remote_router: Some(RemoteRouter {
                receiver_domain: 11155111,
                // the token contract on Ethereum
                receiver_contract:
                    "0x0000000000000000000000000a7c0F5db1f662Ce262f7d2Dcf319CE63df44e12".to_string(),
                gas: "0".to_string(),
            }),
        };

        let resp = ism_client.send_tx(remote_router_enroll_message).await?;
        if !resp.success {
            error!("Failed to enroll remote router: {:?}", resp);
            return Err(anyhow::anyhow!("Failed to enroll remote router"));
        }
        Ok(())
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
    operator.run().await.unwrap();
}

/*
cast send 0x0a7c0F5db1f662Ce262f7d2Dcf319CE63df44e12   "enrollRemoteRouter(uint32,bytes32)"   69420   0x726f757465725f61707000000000000000000000000000010000000000000000   --private-key 52d441beb407f47811a09ed9d330320b2d336482512f26e9a5c5d3dacddc7b1e   --rpc-url https://ethereum-sepolia-rpc.publicnode.com
*/
