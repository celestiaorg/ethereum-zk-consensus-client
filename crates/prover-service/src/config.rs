use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProverConfig {
    pub consensus_rpc_url: String,
    pub evm_rpc_url: String,
    pub mailbox_address: String,
    pub merkle_tree_address: String,
    pub chain_id: u64,
    pub trusted_head: u64,
    pub verifier_id: String,
    pub log_filter: String,
}

impl Default for ProverConfig {
    fn default() -> Self {
        Self {
            consensus_rpc_url: "https://ethereum-sepolia-beacon-api.publicnode.com".to_string(),
            evm_rpc_url: "https://ethereum-sepolia-rpc.publicnode.com".to_string(),
            chain_id: 11155111,
            trusted_head: 9178624,
            mailbox_address: "0xC591542b7C43f1E79Df47526F7459Ed609Aff2a3".to_string(),
            merkle_tree_address: "0xA82571C75164B76721C4047182b73014072E3D9B".to_string(),
            verifier_id: "0x726f757465725f69736d000000000000000000000000002a0000000000000000"
                .to_string(),
            log_filter: "sp1_core=warn,sp1_runtime=warn,sp1_sdk=warn,sp1_vm=warn".to_string(),
        }
    }
}

impl ProverConfig {
    pub fn from_env() -> Result<Self> {
        dotenvy::dotenv().ok();

        let defaults = ProverConfig::default();

        let consensus_rpc_url =
            std::env::var("CONSENSUS_RPC_URL").unwrap_or(defaults.consensus_rpc_url);
        let evm_rpc_url = std::env::var("EVM_RPC_URL").unwrap_or(defaults.evm_rpc_url);
        let mailbox_address = std::env::var("MAILBOX_ADDRESS").unwrap_or(defaults.mailbox_address);
        let merkle_tree_address =
            std::env::var("MERKLE_TREE_ADDRESS").unwrap_or(defaults.merkle_tree_address);
        let chain_id = std::env::var("CHAIN_ID")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(defaults.chain_id);
        let trusted_head = std::env::var("TRUSTED_HEAD")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(defaults.trusted_head);
        let verifier_id = std::env::var("VERIFIER_ID").unwrap_or(defaults.verifier_id);
        let log_filter = std::env::var("LOG_FILTER").unwrap_or(defaults.log_filter);

        Ok(Self {
            consensus_rpc_url,
            evm_rpc_url,
            mailbox_address,
            merkle_tree_address,
            chain_id,
            trusted_head,
            verifier_id,
            log_filter,
        })
    }

    pub fn consensus_rpc_url(&self) -> &str {
        &self.consensus_rpc_url
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn trusted_head(&self) -> u64 {
        self.trusted_head
    }

    pub fn verifier_id(&self) -> &str {
        &self.verifier_id
    }

    pub fn log_filter(&self) -> &str {
        &self.log_filter
    }
}
