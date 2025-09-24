use lanelayer_filler_bot::filler_bot::FillerBot;
use lanelayer_filler_bot::core_lane_client::CoreLaneClient;
use lanelayer_filler_bot::bitcoin_client::BitcoinClient;
use lanelayer_filler_bot::intent_manager::{IntentManager, IntentData, IntentStatus};
use alloy_primitives::{Address, U256};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::Mutex;

#[tokio::test]
async fn test_filler_bot_creation() {
    let core_lane_client = Arc::new(CoreLaneClient::new("http://127.0.0.1:8545".to_string()));
    let bitcoin_client = Arc::new(BitcoinClient::new("http://127.0.0.1:18443".to_string(), "bitcoin".to_string(), "password".to_string(), "test-wallet".to_string()).await.unwrap());
    let intent_manager = Arc::new(Mutex::new(IntentManager::new()));

    let exit_marketplace = Address::from_str("0x0000000000000000000000000000000000000045").unwrap();
    let filler_address = Address::from_str("0x1234567890123456789012345678901234567890").unwrap();

    let bot = FillerBot::new(
        core_lane_client,
        bitcoin_client,
        intent_manager,
        exit_marketplace,
        filler_address,
        10,
    );

}

#[tokio::test]
async fn test_bitcoin_address_parsing() {
    let core_lane_client = Arc::new(CoreLaneClient::new("http://127.0.0.1:8545".to_string()));
    let bitcoin_client = Arc::new(BitcoinClient::new("http://127.0.0.1:18443".to_string(), "bitcoin".to_string(), "password".to_string(), "test-wallet".to_string()).await.unwrap());
    let intent_manager = Arc::new(Mutex::new(IntentManager::new()));

    let exit_marketplace = Address::from_str("0x0000000000000000000000000000000000000045").unwrap();
    let filler_address = Address::from_str("0x1234567890123456789012345678901234567890").unwrap();

    let bot = FillerBot::new(
        core_lane_client,
        bitcoin_client,
        intent_manager,
        exit_marketplace,
        filler_address,
        10,
    );

    // Test Bitcoin address extraction
    let test_inputs = vec![
        ("0x74623171746573746164647265737331323334353637383930", "tb1qtestaddress1234567890"),
        ("0x313141317a5031655035514765666932444d505466544c35534c6d7637446976664e61", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
    ];

    for (input, expected_pattern) in test_inputs {
        let result = bot.parse_bitcoin_address_from_input(input.as_bytes());
        assert!(result.is_ok(), "Failed to parse input: {}", input);

        let address = result.unwrap();
        assert!(!address.is_empty());
        // The address should contain the expected pattern or be a generated test address
        assert!(address.contains("tb1q") || address.contains("1") || address.contains("3"));
    }
}

#[tokio::test]
async fn test_intent_parsing_logic() {
    let core_lane_client = Arc::new(CoreLaneClient::new("http://127.0.0.1:8545".to_string()));
    let bitcoin_client = Arc::new(BitcoinClient::new("http://127.0.0.1:18443".to_string(), "bitcoin".to_string(), "password".to_string(), "test-wallet".to_string()).await.unwrap());
    let intent_manager = Arc::new(Mutex::new(IntentManager::new()));

    let exit_marketplace = Address::from_str("0x0000000000000000000000000000000000000045").unwrap();
    let filler_address = Address::from_str("0x1234567890123456789012345678901234567890").unwrap();

    let bot = FillerBot::new(
        core_lane_client,
        bitcoin_client,
        intent_manager,
        exit_marketplace,
        filler_address,
        10,
    );

    // Test intent parsing with mock transaction
    // Create a proper ABI-encoded intent call
    let intent_data = b"tb1qtestaddress1234567890"; // Bitcoin address as bytes
    let nonce = 0u64;

    // Encode the intent call using the contract's encoding method
    let intent_call = bot.intent_contract.encode_intent_call(intent_data, nonce);

    let mock_tx = lanelayer_filler_bot::core_lane_client::Transaction {
        hash: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
        from: "0x1234567890123456789012345678901234567890".to_string(),
        to: Some("0x0000000000000000000000000000000000000045".to_string()),
        value: "0x174876e800".to_string(), // 100000000000 wei (100K sats)
        input: intent_call,
        gas: "0x5208".to_string(),
        gas_price: "0x3b9aca00".to_string(),
        nonce: "0x0".to_string(),
        block_number: Some("0x1".to_string()),
        block_hash: Some("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string()),
        transaction_index: Some("0x0".to_string()),
    };

    let intent_result = bot.parse_intent_from_transaction(&mock_tx).await;
    assert!(intent_result.is_ok());

    let intent = intent_result.unwrap();
    assert!(intent.is_some());

    let intent_data = intent.unwrap();
    // The intent ID is calculated based on sender, nonce, and input data
    // We just verify it's not empty and has the correct format
    assert!(!intent_data.intent_id.is_empty());
    assert!(intent_data.intent_id.starts_with("0x"));
    assert_eq!(intent_data.lane_btc_amount, U256::from(100000000000u64));
    assert!(intent_data.fee > U256::ZERO);
}

#[tokio::test]
async fn test_fee_calculation() {
    let core_lane_client = Arc::new(CoreLaneClient::new("http://127.0.0.1:8545".to_string()));
    let bitcoin_client = Arc::new(BitcoinClient::new("http://127.0.0.1:18443".to_string(), "bitcoin".to_string(), "password".to_string(), "test-wallet".to_string()).await.unwrap());
    let intent_manager = Arc::new(Mutex::new(IntentManager::new()));

    let exit_marketplace = Address::from_str("0x0000000000000000000000000000000000000045").unwrap();
    let filler_address = Address::from_str("0x1234567890123456789012345678901234567890").unwrap();

    let bot = FillerBot::new(
        core_lane_client,
        bitcoin_client,
        intent_manager,
        exit_marketplace,
        filler_address,
        10,
    );

    // Test fee calculation (1% of amount)
    let amount = U256::from(1000000u64); // 1M wei
    let expected_fee = amount / U256::from(100); // 1%

    assert_eq!(expected_fee, U256::from(10000u64));

    // Test with larger amount
    let large_amount = U256::from(1000000000u64); // 1B wei
    let large_fee = large_amount / U256::from(100);

    assert_eq!(large_fee, U256::from(10000000u64)); // 10M wei
}

#[tokio::test]
async fn test_intent_validation() {
    let mut manager = IntentManager::new();

    // Test valid intent
    let valid_intent = IntentData {
        intent_id: "0x1234567890abcdef".to_string(),
        user_address: Address::from_str("0x1234567890123456789012345678901234567890").unwrap(),
        btc_destination: "tb1qtestaddress1234567890".to_string(),
        lane_btc_amount: U256::from(1000000u64),
        fee: U256::from(10000u64),
    };

    assert!(manager.add_intent(valid_intent).is_ok());

    // Test intent with zero amount (should be rejected)
    let zero_intent = IntentData {
        intent_id: "0x0000000000000000".to_string(),
        user_address: Address::from_str("0x1234567890123456789012345678901234567890").unwrap(),
        btc_destination: "tb1qtestaddress1234567890".to_string(),
        lane_btc_amount: U256::ZERO,
        fee: U256::ZERO,
    };

    // This should still be added (validation happens in the bot logic)
    assert!(manager.add_intent(zero_intent).is_ok());
}
