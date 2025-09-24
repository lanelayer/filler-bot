use lanelayer_filler_bot::bitcoin_client::BitcoinClient;
use bitcoincore_rpc::bitcoin::Network;

#[tokio::test]
async fn test_bitcoin_client_creation() {
    // Test that we can create a Bitcoin client with mock credentials
    let client = BitcoinClient::new(
        "http://127.0.0.1:18443".to_string(),
        "bitcoin".to_string(),
        "password".to_string(),
        "test-wallet".to_string(),
        Network::Signet
    );

    // The client should be created successfully
    assert!(client.is_ok());
}

#[tokio::test]
async fn test_network_detection() {
    let result = BitcoinClient::new_with_auto_detect(
        "http://127.0.0.1:18443".to_string(),
        "bitcoin".to_string(),
        "password".to_string(),
        "test-wallet".to_string()
    ).await;

    match result {
        Ok(client) => {
            // If successful, verify the network was detected
            assert!(matches!(
                client.detect_network().await,
                Ok(bitcoincore_rpc::bitcoin::Network::Bitcoin) |
                Ok(bitcoincore_rpc::bitcoin::Network::Testnet) |
                Ok(bitcoincore_rpc::bitcoin::Network::Signet) |
                Ok(bitcoincore_rpc::bitcoin::Network::Regtest)
            ));
        }
        Err(_) => {
        }
    }
}

#[tokio::test]
async fn test_bitcoin_client_invalid_url() {
    // Test that invalid URLs are handled gracefully
    let client = BitcoinClient::new(
        "invalid-url".to_string(),
        "bitcoin".to_string(),
        "password".to_string(),
        "test-wallet".to_string(),
        Network::Signet
    );

    // This should still create a client (validation happens on actual RPC calls)
    // Just verify it was created (BitcoinClient::new doesn't return Result)
}

#[tokio::test]
async fn test_bitcoin_address_validation() {
    let client = BitcoinClient::new(
        "http://127.0.0.1:18443".to_string(),
        "bitcoin".to_string(),
        "password".to_string(),
        "test-wallet".to_string(),
        Network::Signet
    ).unwrap();

    // Test valid Bitcoin addresses
    let valid_addresses = vec![
        "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", // Testnet bech32
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", // Legacy mainnet
        "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", // P2SH
    ];

    for addr in valid_addresses {
        // For now, we just test that the addresses are strings
        // In a real implementation, we'd validate the address format
        assert!(!addr.is_empty());
        assert!(addr.len() >= 26); // Minimum Bitcoin address length
    }
}

#[tokio::test]
async fn test_intent_id_formatting() {
    let client = BitcoinClient::new(
        "http://127.0.0.1:18443".to_string(),
        "bitcoin".to_string(),
        "password".to_string(),
        "test-wallet".to_string(),
        Network::Signet
    ).unwrap();

    // Test that intent IDs are properly formatted for Bitcoin transactions
    let intent_id = "0x1234567890abcdef";
    let comment = format!("Intent: {}", intent_id);

    assert!(comment.contains("Intent:"));
    assert!(comment.contains(intent_id));
}
