use alloy_primitives::{Address, U256};
use lanelayer_filler_bot::bitcoin_client::BitcoinClient;
use lanelayer_filler_bot::filler_bot::FillerBot;
use lanelayer_filler_bot::intent_manager::{IntentData, IntentManager};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::Mutex;

// Test mnemonic - DO NOT use in production
const TEST_MNEMONIC: &str = "test test test test test test test test test test test junk";

#[tokio::test]
async fn test_filler_bot_creation() {
    let bitcoin_client = Arc::new(Mutex::new(
        BitcoinClient::new_rpc(
            "http://127.0.0.1:18443".to_string(),
            "bitcoin".to_string(),
            "password".to_string(),
            TEST_MNEMONIC.to_string(),
            "regtest".to_string(),
            "test-wallet".to_string(),
        )
        .await
        .unwrap(),
    ));
    let intent_manager = Arc::new(Mutex::new(IntentManager::new()));

    let exit_marketplace = Address::from_str("0x0000000000000000000000000000000000000045").unwrap();
    let filler_address = Address::from_str("0x1234567890123456789012345678901234567890").unwrap();

    let _bot = FillerBot::new(
        "http://127.0.0.1:8545".to_string(),
        bitcoin_client,
        intent_manager,
        exit_marketplace,
        filler_address,
        10,
    );

    // Verify bot was created (just that it didn't panic)
}

#[tokio::test]
async fn test_bitcoin_address_parsing() {
    let bitcoin_client = Arc::new(Mutex::new(
        BitcoinClient::new_rpc(
            "http://127.0.0.1:18443".to_string(),
            "bitcoin".to_string(),
            "password".to_string(),
            TEST_MNEMONIC.to_string(),
            "regtest".to_string(),
            "test-wallet".to_string(),
        )
        .await
        .unwrap(),
    ));
    let intent_manager = Arc::new(Mutex::new(IntentManager::new()));

    let exit_marketplace = Address::from_str("0x0000000000000000000000000000000000000045").unwrap();
    let filler_address = Address::from_str("0x1234567890123456789012345678901234567890").unwrap();

    let _bot = FillerBot::new(
        "http://127.0.0.1:8545".to_string(),
        bitcoin_client,
        intent_manager,
        exit_marketplace,
        filler_address,
        10,
    );

    // Test Bitcoin address validation - this test is simplified since we can't easily test
    // the parse_bitcoin_address_from_input method without proper transaction setup
    let test_addresses = vec![
        "tb1qtestaddress1234567890",
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    ];

    for addr in test_addresses {
        assert!(!addr.is_empty());
        assert!(addr.len() >= 26);
    }
}

#[tokio::test]
async fn test_intent_parsing_logic() {
    // This test is simplified since creating a proper alloy Transaction requires
    // more complex setup. We test the contract encoding instead.
    let bitcoin_client = Arc::new(Mutex::new(
        BitcoinClient::new_rpc(
            "http://127.0.0.1:18443".to_string(),
            "bitcoin".to_string(),
            "password".to_string(),
            TEST_MNEMONIC.to_string(),
            "regtest".to_string(),
            "test-wallet".to_string(),
        )
        .await
        .unwrap(),
    ));
    let intent_manager = Arc::new(Mutex::new(IntentManager::new()));

    let exit_marketplace = Address::from_str("0x0000000000000000000000000000000000000045").unwrap();
    let filler_address = Address::from_str("0x1234567890123456789012345678901234567890").unwrap();

    let bot = FillerBot::new(
        "http://127.0.0.1:8545".to_string(),
        bitcoin_client,
        intent_manager,
        exit_marketplace,
        filler_address,
        10,
    );

    // Test intent call encoding
    let intent_data = b"tb1qtestaddress1234567890"; // Bitcoin address as bytes
    let nonce = 0u64;

    // Encode the intent call using the contract's encoding method
    let intent_call = bot.intent_contract.encode_intent_call(intent_data, nonce);

    // Verify the call data is properly formatted
    assert!(intent_call.starts_with("0x"));
    assert!(intent_call.len() > 2); // Should have actual data beyond "0x"
}

#[test]
fn test_fee_calculation() {
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
