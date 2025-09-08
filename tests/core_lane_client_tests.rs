use lanelayer_filler_bot::core_lane_client::CoreLaneClient;
use alloy_primitives::Address;
use std::str::FromStr;

#[tokio::test]
async fn test_core_lane_client_creation() {
    // Test that we can create a Core Lane client
    let client = CoreLaneClient::new("http://127.0.0.1:8545".to_string());

    // The client should be created successfully (CoreLaneClient::new doesn't return Result)
    // Just verify it was created
}

#[tokio::test]
async fn test_core_lane_client_invalid_url() {
    // Test that invalid URLs are handled gracefully
    let client = CoreLaneClient::new("invalid-url".to_string());

    // This should still create a client (validation happens on actual RPC calls)
    // Just verify it was created
}

#[tokio::test]
async fn test_address_parsing() {
    // Test that we can parse Ethereum addresses correctly
    let valid_addresses = vec![
        "0x1234567890123456789012345678901234567890",
        "0x0000000000000000000000000000000000000045", // Exit marketplace
        "0x000000000000000000000000000000000000dead", // Burn address
    ];

    for addr_str in valid_addresses {
        let addr = Address::from_str(addr_str);
        assert!(addr.is_ok(), "Failed to parse address: {}", addr_str);
    }
}

#[tokio::test]
async fn test_exit_marketplace_address() {
    // Test the specific exit marketplace address
    let exit_marketplace = Address::from_str("0x0000000000000000000000000000000000000045").unwrap();

    // Verify it's the correct address
    assert_eq!(exit_marketplace.to_string(), "0x0000000000000000000000000000000000000045");
}

#[tokio::test]
async fn test_burn_address() {
    // Test the burn address
    let burn_address = Address::from_str("0x000000000000000000000000000000000000dead").unwrap();

    // Verify it's the correct address (case insensitive)
    assert_eq!(burn_address.to_string().to_lowercase(), "0x000000000000000000000000000000000000dead");
}

#[tokio::test]
async fn test_transaction_data_parsing() {
    // Test parsing of transaction data
    let mock_tx_data = "0x1234567890abcdef";
    let input_hex = mock_tx_data.trim_start_matches("0x");

    // Should be able to decode hex
    let decoded = hex::decode(input_hex);
    assert!(decoded.is_ok());

    let bytes = decoded.unwrap();
    assert_eq!(bytes.len(), 8);
}

#[tokio::test]
async fn test_block_number_parsing() {
    // Test parsing of block numbers
    let block_numbers = vec![
        "0x0",
        "0x1",
        "0x123",
        "0xabc",
        "0x1000",
    ];

    for block_hex in block_numbers {
        let block_num = u64::from_str_radix(block_hex.trim_start_matches("0x"), 16);
        assert!(block_num.is_ok(), "Failed to parse block number: {}", block_hex);
    }
}
