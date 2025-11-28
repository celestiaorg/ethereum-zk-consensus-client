use sp1_sdk::include_elf;

pub const MOCK_ELF: &[u8] = include_elf!("mock");
const GROTH16_VK: &[u8] = include_bytes!("../../../groth16_vk.bin");

#[cfg(test)]
mod tests {
    use crate::{GROTH16_VK, MOCK_ELF};
    use celestia_grpc_client::CelestiaIsmClient;
    use celestia_grpc_client::proto::celestia::zkism::v1::QueryIsmRequest;
    use celestia_grpc_client::types::ClientConfig;
    use sp1_sdk::{HashableKey, ProverClient, SP1Stdin};
    use types::MockTrustedState;
    use types::{MsgCreateConsensusISM, MsgUpdateConsensusISM};

    #[tokio::test]
    async fn test_mock_circuit() {
        dotenvy::dotenv().ok();
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
        println!(
            "Initial trusted state bytes: {:?}",
            initial_trusted_state_bytes
        );

        let prover_client = ProverClient::from_env();
        let (pk, vk) = prover_client.setup(MOCK_ELF);

        let ism_client = CelestiaIsmClient::new(ClientConfig::from_env().unwrap())
            .await
            .unwrap();

        // create verifier module from trusted state
        let create_message = MsgCreateConsensusISM {
            creator: ism_client.signer_address().to_string(),
            trusted_state: initial_trusted_state_bytes,
            groth16_vkey: GROTH16_VK.to_vec(),
            state_transition_vkey: vk.bytes32_raw().to_vec(),
        };
        let response = ism_client.send_tx(create_message).await.unwrap();
        println!("Submitted create message: {:?}", response);
        // submit proof to update verifier module

        let mut stdin = SP1Stdin::new();
        stdin.write(&initial_trusted_state);
        let proof = prover_client.prove(&pk, &stdin).groth16().run().unwrap();

        let update_message = MsgUpdateConsensusISM {
            id: "0x726f757465725f69736d000000000000000000000000002a0000000000000000".to_string(),
            proof: proof.bytes(),
            public_values: proof.public_values.to_vec(),
            signer: ism_client.signer_address().to_string(),
        };

        println!(
            "Public values: {:?}, length: {}",
            proof.public_values.to_vec(),
            proof.public_values.to_vec().len()
        );
        let response = ism_client.send_tx(update_message).await.unwrap();
        println!("Submitted update message: {:?}", response);

        let verifier_response = ism_client
            .verifier(QueryIsmRequest {
                id: "0x726f757465725f69736d000000000000000000000000002a0000000000000000"
                    .to_string(),
            })
            .await
            .unwrap();
        let ism = verifier_response.ism.unwrap();
        let trusted_state: MockTrustedState = bincode::deserialize(&ism.state).unwrap();

        println!("Verifier Trusted State: {:?}", trusted_state);
    }
}
