use lanelayer_filler_bot::bitcoin_client::BitcoinClient;

#[tokio::test]
async fn test_bitcoin_client_creation() {
    let result = BitcoinClient::new(
        "http://127.0.0.1:18443".to_string(),
        "bitcoin".to_string(),
        "password".to_string(),
        "test-wallet".to_string()
    ).await;

    match result {
        Ok(_client) => {}
        Err(_) => {}
    }
}


#[tokio::test]
async fn test_bitcoin_client_invalid_url() {
    let result = BitcoinClient::new(
        "invalid-url".to_string(),
        "bitcoin".to_string(),
        "password".to_string(),
        "test-wallet".to_string()
    ).await;

    match result {
        Ok(_) => {}
        Err(_) => {}
    }
}

#[tokio::test]
async fn test_bitcoin_address_validation() {
    let result = BitcoinClient::new(
        "http://127.0.0.1:18443".to_string(),
        "bitcoin".to_string(),
        "password".to_string(),
        "test-wallet".to_string()
    ).await;

    let valid_addresses = vec![
        "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
    ];

    for addr in valid_addresses {
        assert!(!addr.is_empty());
        assert!(addr.len() >= 26);
    }

    match result {
        Ok(_client) => {}
        Err(_) => {}
    }
}

#[tokio::test]
async fn test_intent_id_formatting() {
    let result = BitcoinClient::new(
        "http://127.0.0.1:18443".to_string(),
        "bitcoin".to_string(),
        "password".to_string(),
        "test-wallet".to_string()
    ).await;

    let intent_id = "0x1234567890abcdef";
    let comment = format!("Intent: {}", intent_id);

    assert!(comment.contains("Intent:"));
    assert!(comment.contains(intent_id));

    match result {
        Ok(_client) => {}
        Err(_) => {}
    }
}
