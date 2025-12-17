use crate::error::{IsmClientError, Result};
use crate::proto::celestia::zkism::v1::{
    query_client::QueryClient, QueryIsmRequest, QueryIsmResponse, QueryIsmsRequest,
    QueryIsmsResponse,
};
use crate::types::{ClientConfig, TxResponse, TypedTxResponse};

use anyhow::Context;
use celestia_grpc::{GrpcClient, IntoProtobufAny};
use prost::Message;
use tonic::{
    transport::{Channel, Endpoint},
    Request,
};
use tracing::{debug, info, warn};

/// Celestia gRPC client for proof submission
#[derive(Clone)]
pub struct CelestiaIsmClient {
    pub config: ClientConfig,
    channel: Channel,
    tx_client: GrpcClient,
}

impl CelestiaIsmClient {
    /// Create a new Celestia proof client
    pub async fn new(config: ClientConfig) -> Result<Self> {
        debug!(
            "Creating Celestia proof client with endpoint: {}",
            config.grpc_endpoint
        );

        // optional: set timeouts, concurrency limits, TLS, etc.
        let endpoint = Endpoint::from_shared(config.grpc_endpoint.clone())?
            .connect_timeout(std::time::Duration::from_secs(15))
            .tcp_nodelay(true);

        let channel = endpoint.connect().await?;

        let tx_client = GrpcClient::builder()
            .url(&config.grpc_endpoint)
            .private_key_hex(&config.private_key_hex)
            .build()
            .context("Failed to build Lumina gRPC client")?;

        info!("Successfully created Celestia proof client");

        Ok(Self {
            config,
            channel,
            tx_client,
        })
    }

    /// Get the gRPC tx client reference for direct access to Lumina functionality
    pub fn tx_client(&self) -> &GrpcClient {
        &self.tx_client
    }

    /// Get the client configuration
    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    /// Get the configured chain ID
    pub fn chain_id(&self) -> &str {
        &self.config.chain_id
    }

    /// Get the configured ism ID
    pub fn ism_id(&self) -> &str {
        &self.config.ism_id
    }

    /// Get the configured gRPC endpoint
    pub fn grpc_endpoint(&self) -> &str {
        &self.config.grpc_endpoint
    }

    /// Get the cached bech32-encoded signer address
    pub fn signer_address(&self) -> &str {
        &self.config.signer_address
    }

    pub async fn ism(&self, req: QueryIsmRequest) -> Result<QueryIsmResponse> {
        let mut client = QueryClient::new(self.channel.clone());
        let resp = client.ism(Request::new(req)).await?;
        Ok(resp.into_inner())
    }

    pub async fn verifier(&self, req: QueryIsmRequest) -> Result<QueryIsmResponse> {
        let mut client = QueryClient::new(self.channel.clone());
        let resp = client.ism(Request::new(req)).await?;
        Ok(resp.into_inner())
    }

    pub async fn isms(&self, req: QueryIsmsRequest) -> Result<QueryIsmsResponse> {
        let mut client = QueryClient::new(self.channel.clone());
        let resp = client.isms(Request::new(req)).await?;
        Ok(resp.into_inner())
    }

    pub async fn verifiers(&self, req: QueryIsmRequest) -> Result<QueryIsmResponse> {
        let mut client = QueryClient::new(self.channel.clone());
        let resp = client.ism(Request::new(req)).await?;
        Ok(resp.into_inner())
    }

    /// Sign and send a tx to Celestia including the provided message.
    pub async fn send_tx<M>(&self, message: M) -> Result<TxResponse>
    where
        M: Message + IntoProtobufAny + Send + Clone + 'static,
    {
        let message_type = message.clone().into_any().type_url;
        debug!(
            "Submitting {} message to Celestia (endpoint: {}, chain: {})",
            message_type, self.config.grpc_endpoint, self.config.chain_id
        );

        let tx_config = celestia_grpc::TxConfig {
            gas_limit: Some(self.config.max_gas),
            gas_price: Some(self.config.gas_price as f64),
            memo: Some("celestia-zkism-client".to_string()),
            ..Default::default()
        };

        match self.tx_client.submit_message(message, tx_config).await {
            Ok(tx_info) => {
                info!(
                    "Successfully submitted {} message: tx_hash={}, height={}",
                    message_type,
                    tx_info.hash,
                    tx_info.height.value()
                );

                Ok(TxResponse {
                    tx_hash: tx_info.hash.to_string(),
                    height: tx_info.height.value(),
                    gas_used: 0, // TxInfo doesn't provide gas_used, use estimation
                    success: true,
                    error_message: None,
                    data: None,
                })
            }
            Err(e) => {
                warn!("Failed to submit {} message: {}", message_type, e);
                Err(IsmClientError::TxFailed(format!(
                    "Failed to submit {message_type}: {e}"
                )))
            }
        }
    }

    /// Sign and send a tx to Celestia and decode the typed response.
    ///
    /// This method queries the transaction after broadcast to retrieve the response data
    /// and decodes it into the expected response type.
    pub async fn send_tx_typed<M, R>(&self, message: M) -> Result<TypedTxResponse<R>>
    where
        M: Message + IntoProtobufAny + Send + Clone + 'static,
        R: Message + Default,
    {
        let message_type = message.clone().into_any().type_url;
        debug!(
            "Submitting {} message to Celestia (endpoint: {}, chain: {})",
            message_type, self.config.grpc_endpoint, self.config.chain_id
        );

        let tx_config = celestia_grpc::TxConfig {
            gas_limit: Some(self.config.max_gas),
            gas_price: Some(self.config.gas_price as f64),
            memo: Some("celestia-zkism-client".to_string()),
            ..Default::default()
        };

        match self.tx_client.submit_message(message, tx_config).await {
            Ok(tx_info) => {
                info!(
                    "Successfully submitted {} message: tx_hash={}, height={}",
                    message_type,
                    tx_info.hash,
                    tx_info.height.value()
                );

                // Query the transaction to get the response data
                let tx_result = self.tx_client.get_tx(tx_info.hash).await.map_err(|e| {
                    IsmClientError::TxFailed(format!("Failed to query tx result: {e}"))
                })?;

                let data_hex = &tx_result.tx_response.data;
                let data_bytes = hex::decode(data_hex).map_err(|e| {
                    IsmClientError::TxFailed(format!("Failed to decode response data hex: {e}"))
                })?;

                // The data field contains a TxMsgData protobuf which wraps the actual response
                // For simplicity, we attempt to decode the response directly
                // In Cosmos SDK, the data is typically: TxMsgData { msg_responses: [Any { type_url, value }] }
                let response = decode_msg_response::<R>(&data_bytes)?;

                Ok(TypedTxResponse {
                    tx: TxResponse {
                        tx_hash: tx_info.hash.to_string(),
                        height: tx_info.height.value(),
                        gas_used: 0,
                        success: true,
                        error_message: None,
                        data: Some(data_hex.clone()),
                    },
                    response,
                })
            }
            Err(e) => {
                warn!("Failed to submit {} message: {}", message_type, e);
                Err(IsmClientError::TxFailed(format!(
                    "Failed to submit {message_type}: {e}"
                )))
            }
        }
    }
}

/// Decode the message response from TxMsgData bytes.
///
/// In Cosmos SDK, the tx response data contains a TxMsgData protobuf:
/// ```protobuf
/// message TxMsgData {
///   repeated Any msg_responses = 2;
/// }
/// ```
fn decode_msg_response<R: Message + Default>(data: &[u8]) -> Result<R> {
    use prost::bytes::Bytes;

    // TxMsgData structure (simplified inline decoding)
    // Field 2 (msg_responses) is a repeated Any
    // Each Any has: field 1 = type_url (string), field 2 = value (bytes)

    let mut cursor = data;

    // Skip through the protobuf looking for field 2 (msg_responses)
    while !cursor.is_empty() {
        let (field_number, wire_type) = prost::encoding::decode_key(&mut cursor)
            .map_err(|e| IsmClientError::TxFailed(format!("Failed to decode protobuf key: {e}")))?;

        if field_number == 2 {
            // This is msg_responses (length-delimited Any)
            let len = prost::encoding::decode_varint(&mut cursor)
                .map_err(|e| IsmClientError::TxFailed(format!("Failed to decode length: {e}")))?
                as usize;

            if cursor.len() < len {
                return Err(IsmClientError::TxFailed(
                    "Invalid protobuf: not enough bytes".to_string(),
                ));
            }

            let any_bytes = &cursor[..len];

            // Parse the Any message to extract the value field (field 2)
            let mut any_cursor = any_bytes;
            while !any_cursor.is_empty() {
                let (any_field, any_wire) =
                    prost::encoding::decode_key(&mut any_cursor).map_err(|e| {
                        IsmClientError::TxFailed(format!("Failed to decode Any key: {e}"))
                    })?;

                if any_field == 2 && any_wire == prost::encoding::WireType::LengthDelimited {
                    // This is the value field containing the actual response
                    let value_len =
                        prost::encoding::decode_varint(&mut any_cursor).map_err(|e| {
                            IsmClientError::TxFailed(format!("Failed to decode value length: {e}"))
                        })? as usize;

                    if any_cursor.len() < value_len {
                        return Err(IsmClientError::TxFailed(
                            "Invalid protobuf: not enough bytes for value".to_string(),
                        ));
                    }

                    let value_bytes = &any_cursor[..value_len];
                    return R::decode(Bytes::copy_from_slice(value_bytes)).map_err(|e| {
                        IsmClientError::TxFailed(format!("Failed to decode response: {e}"))
                    });
                } else {
                    // Skip this field
                    prost::encoding::skip_field(
                        any_wire,
                        any_field,
                        &mut any_cursor,
                        Default::default(),
                    )
                    .map_err(|e| {
                        IsmClientError::TxFailed(format!("Failed to skip Any field: {e}"))
                    })?;
                }
            }
        } else {
            // Skip this field
            prost::encoding::skip_field(wire_type, field_number, &mut cursor, Default::default())
                .map_err(|e| IsmClientError::TxFailed(format!("Failed to skip field: {e}")))?;
        }
    }

    Err(IsmClientError::TxFailed(
        "No msg_response found in TxMsgData".to_string(),
    ))
}
#[cfg(test)]
mod tests {
    use crate::message::{StateInclusionProofMsg, StateTransitionProofMsg};
    use prost::Message;

    use super::*;

    #[allow(dead_code)]
    fn create_test_config() -> ClientConfig {
        ClientConfig {
            grpc_endpoint: "http://localhost:9090".to_string(),
            private_key_hex: "0123456789abcdef".repeat(8), // 64 hex chars
            signer_address: String::new(),                 // Will be derived
            chain_id: "test-chain".to_string(),
            ism_id: String::new(),
            gas_price: 1000,
            max_gas: 200_000,
            confirmation_timeout: 30,
        }
    }

    #[test]
    fn test_state_transition_proof_message_structure() {
        // Test the new message structure based on actual Celestia PR #5788
        let proof_msg = StateTransitionProofMsg::new(
            "".to_string(),            // Empty ISM ID should be validated
            vec![1, 2, 3],             // proof
            vec![4, 5, 6],             // public_values
            "test_signer".to_string(), // signer
        );

        // Test the new field structure
        assert_eq!(proof_msg.id, "");
        assert_eq!(proof_msg.proof, vec![1, 2, 3]);
        assert_eq!(proof_msg.public_values, vec![4, 5, 6]);
        assert_eq!(proof_msg.signer, "test_signer");
    }

    #[test]
    fn test_state_inclusion_proof_message_structure() {
        // Test the new message structure based on actual Celestia PR #5790
        let proof_msg = StateInclusionProofMsg::new(
            "test-ism".to_string(),    // ISM ID
            vec![7, 8, 9],             // proof
            vec![10, 11, 12],          // public_values
            "test_signer".to_string(), // signer
        );

        // Test the new field structure
        assert_eq!(proof_msg.id, "test-ism");
        assert_eq!(proof_msg.proof, vec![7, 8, 9]);
        assert_eq!(proof_msg.public_values, vec![10, 11, 12]);
        assert_eq!(proof_msg.signer, "test_signer");
    }

    #[test]
    fn test_message_serialization() {
        let proof_msg = StateTransitionProofMsg::new(
            "test-ism-123".to_string(),
            vec![0xff, 0xee, 0xdd],
            vec![0x01, 0x02, 0x03],
            "test_signer".to_string(),
        );

        // Test that the message can be serialized (this validates the structure)
        let serialized = proof_msg.encode_to_vec();
        assert!(!serialized.is_empty());

        // Test deserialization
        let deserialized: StateTransitionProofMsg =
            StateTransitionProofMsg::decode(serialized.as_slice()).expect("failed to decode");

        assert_eq!(deserialized.id, proof_msg.id);
        assert_eq!(deserialized.proof, proof_msg.proof);
        assert_eq!(deserialized.public_values, proof_msg.public_values);
        assert_eq!(deserialized.signer, proof_msg.signer);
    }

    #[test]
    fn test_client_config_usage() {
        let config = create_test_config();

        // Test that config fields are accessible and properly structured
        assert_eq!(config.grpc_endpoint, "http://localhost:9090");
        assert_eq!(config.chain_id, "test-chain");
        assert_eq!(config.gas_price, 1000);
        assert_eq!(config.max_gas, 200_000);
        assert_eq!(config.confirmation_timeout, 30);

        // Test that private key is properly formatted (64 hex chars)
        assert_eq!(config.private_key_hex.len(), 128); // 64 bytes * 2 chars per byte
    }
}
