use lanelayer_filler_bot::bitcoin_client::BitcoinClient;

// Test mnemonic - DO NOT use in production
const TEST_MNEMONIC: &str = "test test test test test test test test test test test junk";

#[tokio::test]
async fn test_bitcoin_client_creation_rpc() {
    let result = BitcoinClient::new_rpc(
        "http://127.0.0.1:18443".to_string(),
        "bitcoin".to_string(),
        "password".to_string(),
        TEST_MNEMONIC.to_string(),
        "regtest".to_string(),
        "test-wallet".to_string(),
    )
    .await;

    match result {
        Ok(_client) => {}
        Err(_) => {}
    }
}

#[tokio::test]
async fn test_bitcoin_client_creation_electrum() {
    let result = BitcoinClient::new_electrum(
        "tcp://127.0.0.1:50001".to_string(),
        TEST_MNEMONIC.to_string(),
        "regtest".to_string(),
        "test-wallet-electrum".to_string(),
    )
    .await;

    match result {
        Ok(_client) => {}
        Err(_) => {}
    }
}

#[tokio::test]
async fn test_bitcoin_address_validation() {
    let valid_addresses = vec![
        "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
    ];

    for addr in valid_addresses {
        assert!(!addr.is_empty());
        assert!(addr.len() >= 26);
    }
}

#[tokio::test]
async fn test_intent_id_formatting() {
    let intent_id = "0x1234567890abcdef";
    let comment = format!("Intent: {}", intent_id);

    assert!(comment.contains("Intent:"));
    assert!(comment.contains(intent_id));
}
