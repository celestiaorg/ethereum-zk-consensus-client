use std::sync::Arc;

use alloy::rpc::types::Filter;
use alloy_primitives::Address;
use ev_state_queries::{DefaultProvider, hyperlane::indexer::HyperlaneIndexer};
use ev_zkevm_types::events::Dispatch;
use tracing::debug;
use zkevm_storage::hyperlane::message::HyperlaneMessageStore;

pub async fn index_sepolia(
    start_height: u64,
    end_height: u64,
    mailbox_address: Address,
    storage: Arc<HyperlaneMessageStore>,
    provider: DefaultProvider,
) -> Result<(), anyhow::Error> {
    let mut current_height = start_height;
    while current_height < end_height {
        let to_block = (current_height + 10000).min(end_height);
        debug!(
            "Indexing messages from height {} to {}",
            current_height, to_block
        );
        let filter = Filter::new()
            .address(mailbox_address)
            .event(&Dispatch::id())
            .from_block(current_height)
            .to_block(to_block);
        let indexer: HyperlaneIndexer = HyperlaneIndexer::new(filter.clone());
        indexer
            .process(filter, provider.clone(), storage.clone())
            .await?;
        current_height = to_block;
    }
    Ok(())
}

#[tokio::test]
async fn test_index_sepolia() {
    use alloy::providers::ProviderBuilder;
    use reqwest::Url;
    use std::str::FromStr;
    use zkevm_storage::hyperlane::StoredHyperlaneMessage;

    let evm_provider = ProviderBuilder::new()
        .connect_http(Url::parse("https://ethereum-sepolia-rpc.publicnode.com").unwrap());

    let storage_path = dirs::home_dir()
        .expect("cannot find home directory")
        .join(".ev-prover")
        .join("data");

    let hyperlane_message_store =
        Arc::new(HyperlaneMessageStore::new(storage_path.clone()).unwrap());

    crate::hyperlane::index_sepolia(
        0,
        9853049,
        Address::from_str("0xC591542b7C43f1E79Df47526F7459Ed609Aff2a3").unwrap(),
        hyperlane_message_store.clone(),
        evm_provider.clone().into(),
    )
    .await
    .unwrap();

    // prove and submit indexed messages
    let mut messages: Vec<StoredHyperlaneMessage> = Vec::new();
    for block in 9000000..=9853049 {
        messages.extend(hyperlane_message_store.get_by_block(block).unwrap());
    }

    println!("Messages: {:?}", messages);
}
