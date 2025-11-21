use sp1_sdk::include_elf;

pub const MOCK_ELF: &[u8] = include_elf!("mock");
const GROTH16_VK: &[u8] = include_bytes!("../../../groth16_vk.bin");

#[cfg(test)]
mod tests {
    use crate::{GROTH16_VK, MOCK_ELF};
    use celestia_grpc::{GrpcClient, TxConfig};
    use sp1_sdk::{HashableKey, ProverClient, SP1Stdin};
    use types::MockTrustedState;
    use types::{MsgCreateStateTransitionVerifier, MsgUpdateStateTransitionVerifier};

    #[tokio::test]
    async fn test_mock_circuit() {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .unwrap();

        let initial_trusted_state = MockTrustedState {
            previous_height: 0,
            previous_root: [0; 32],
            new_height: 0,
            new_root: [0; 32],
        };

        let initial_trusted_state_bytes = bincode::serialize(&initial_trusted_state).unwrap();

        let prover_client = ProverClient::from_env();
        let (pk, vk) = prover_client.setup(MOCK_ELF);

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
}
