use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProverConfig {
    pub consensus_rpc_url: String,
    pub evm_rpc_url: String,
    pub chain_id: u64,
    pub trusted_head: u64,
    pub indexer_execution_height: u64,
    pub trusted_execution_block_number: u64,
    pub mailbox_address: String,
    pub remote_mailbox_address: String,
    pub merkle_tree_address: String,
    pub ethereum_token_address: String,
    pub log_filter: String,
    pub timeout: u64,
}

impl Default for ProverConfig {
    fn default() -> Self {
        Self {
            consensus_rpc_url: "https://ethereum-sepolia-beacon-api.publicnode.com".to_string(),
            evm_rpc_url: "https://ethereum-sepolia-rpc.publicnode.com".to_string(),
            chain_id: 11155111,
            trusted_head: 9178624,
            indexer_execution_height: 9000000,
            trusted_execution_block_number: 0,
            mailbox_address: "0xC591542b7C43f1E79Df47526F7459Ed609Aff2a3".to_string(),
            remote_mailbox_address:
                "0x68797065726c616e650000000000000000000000000000000000000000000000".to_string(),
            merkle_tree_address: "0xA82571C75164B76721C4047182b73014072E3D9B".to_string(),
            // native token on Ethereum (Sepolia)
            ethereum_token_address:
                "0x0000000000000000000000000a7c0F5db1f662Ce262f7d2Dcf319CE63df44e12".to_string(),
            log_filter: "sp1_core=warn,sp1_runtime=warn,sp1_sdk=warn,sp1_vm=warn".to_string(),
            timeout: 600, // 10 minutes
        }
    }
}

impl ProverConfig {
    pub fn from_env() -> Result<Self> {
        dotenvy::dotenv().ok();
        let defaults = ProverConfig::default();
        let chain_id = std::env::var("CHAIN_ID")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(defaults.chain_id);
        let trusted_head = std::env::var("TRUSTED_HEAD")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(defaults.trusted_head);
        let consensus_rpc_url =
            std::env::var("CONSENSUS_RPC_URL").unwrap_or(defaults.consensus_rpc_url);
        let evm_rpc_url = std::env::var("EVM_RPC_URL").unwrap_or(defaults.evm_rpc_url);
        let remote_mailbox_address =
            std::env::var("REMOTE_MAILBOX_ADDRESS").unwrap_or(defaults.remote_mailbox_address);
        let mailbox_address = std::env::var("MAILBOX_ADDRESS").unwrap_or(defaults.mailbox_address);
        let merkle_tree_address =
            std::env::var("MERKLE_TREE_ADDRESS").unwrap_or(defaults.merkle_tree_address);
        let ethereum_token_address =
            std::env::var("ETHEREUM_TOKEN_ADDRESS").unwrap_or(defaults.ethereum_token_address);
        let log_filter = std::env::var("LOG_FILTER").unwrap_or(defaults.log_filter);
        let timeout = std::env::var("PROVER_TIMEOUT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(defaults.timeout);
        let indexer_execution_height = std::env::var("INDEXER_EXECUTION_HEIGHT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(defaults.indexer_execution_height);
        let trusted_execution_block_number = std::env::var("TRUSTED_EXECUTION_BLOCK_NUMBER")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(defaults.trusted_execution_block_number);

        Ok(Self {
            consensus_rpc_url,
            evm_rpc_url,
            chain_id,
            trusted_head,
            indexer_execution_height,
            trusted_execution_block_number,
            mailbox_address,
            merkle_tree_address,
            remote_mailbox_address,
            ethereum_token_address,
            log_filter,
            timeout,
        })
    }

    pub fn consensus_rpc_url(&self) -> &str {
        &self.consensus_rpc_url
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn indexer_execution_height(&self) -> u64 {
        self.indexer_execution_height
    }

    pub fn trusted_execution_block_number(&self) -> u64 {
        self.trusted_execution_block_number
    }

    pub fn ethereum_token_address(&self) -> &str {
        &self.ethereum_token_address
    }

    pub fn remote_mailbox_address(&self) -> &str {
        &self.remote_mailbox_address
    }

    pub fn trusted_head(&self) -> u64 {
        self.trusted_head
    }

    pub fn log_filter(&self) -> &str {
        &self.log_filter
    }
}
