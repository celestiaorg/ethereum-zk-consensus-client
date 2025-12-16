use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProverConfig {
    consensus_rpc_url: String,
    chain_id: u64,
    trusted_head: u64,
    verifier_id: String,
    log_filter: String,
}

impl Default for ProverConfig {
    fn default() -> Self {
        Self {
            consensus_rpc_url: "https://ethereum-sepolia-beacon-api.publicnode.com".to_string(),
            chain_id: 11155111,
            trusted_head: 9178624,
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
