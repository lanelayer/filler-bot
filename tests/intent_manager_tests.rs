use alloy_primitives::{Address, U256};
use lanelayer_filler_bot::intent_manager::{IntentData, IntentManager, IntentStatus};
use std::str::FromStr;

#[test]
fn test_intent_manager_basic_operations() {
    let mut manager = IntentManager::new();

    // Create a test intent
    let intent_data = IntentData {
        intent_id: "0x1234567890abcdef".to_string(),
        user_address: Address::from_str("0x1234567890123456789012345678901234567890").unwrap(),
        btc_destination: "tb1qexample1234567890abcdefghijklmnopqrstuvwxyz".to_string(),
        lane_btc_amount: U256::from(1000000u64),
        fee: U256::from(10000u64),
    };

    // Test adding an intent
    assert!(manager.add_intent(intent_data).is_ok());
    assert_eq!(manager.get_intent_count(), 1);
    assert_eq!(manager.get_intent_count_by_status(IntentStatus::Pending), 1);

    // Test getting pending intents
    let pending = manager.get_pending_intents();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].intent_id, "0x1234567890abcdef");

    // Test updating status
    assert!(manager
        .update_intent_status("0x1234567890abcdef", IntentStatus::Locked)
        .is_ok());
    assert_eq!(manager.get_intent_count_by_status(IntentStatus::Locked), 1);
    assert_eq!(manager.get_intent_count_by_status(IntentStatus::Pending), 0);
}

#[test]
fn test_intent_fulfillment_calculation() {
    let manager = IntentManager::new();

    let intent_data = IntentData {
        intent_id: "0x1234567890abcdef".to_string(),
        user_address: Address::from_str("0x1234567890123456789012345678901234567890").unwrap(),
        btc_destination: "tb1qexample1234567890abcdefghijklmnopqrstuvwxyz".to_string(),
        lane_btc_amount: U256::from(1000000u64), // 1M sats
        fee: U256::from(10000u64),               // 10K sats
    };

    let intent = lanelayer_filler_bot::intent_manager::UserIntent {
        intent_id: intent_data.intent_id,
        user_address: intent_data.user_address,
        btc_destination: intent_data.btc_destination,
        lane_btc_amount: intent_data.lane_btc_amount,
        fee: intent_data.fee,
        status: IntentStatus::Pending,
        created_at: chrono::Utc::now(),
        bitcoin_txid: None,
        bitcoin_confirmations: None,
    };

    // Test with sufficient balance
    assert!(manager.can_fulfill_intent(&intent, 2000000)); // 2M sats available

    // Test with insufficient balance
    assert!(!manager.can_fulfill_intent(&intent, 500000)); // 500K sats available
}

#[test]
fn test_intent_id_generation() {
    let intent_id1 = IntentManager::generate_test_intent_id();
    let intent_id2 = IntentManager::generate_test_intent_id();

    // Should be different
    assert_ne!(intent_id1, intent_id2);

    // Should start with 0x
    assert!(intent_id1.starts_with("0x"));
    assert!(intent_id2.starts_with("0x"));

    // Should be valid hex
    assert!(intent_id1.len() > 2);
    assert!(intent_id2.len() > 2);
}

#[test]
fn test_intent_status_transitions() {
    let mut manager = IntentManager::new();

    let intent_data = IntentData {
        intent_id: "0x1234567890abcdef".to_string(),
        user_address: Address::from_str("0x1234567890123456789012345678901234567890").unwrap(),
        btc_destination: "tb1qexample1234567890abcdefghijklmnopqrstuvwxyz".to_string(),
        lane_btc_amount: U256::from(1000000u64),
        fee: U256::from(10000u64),
    };

    manager.add_intent(intent_data).unwrap();

    // Test status transitions
    assert_eq!(manager.get_intent_count_by_status(IntentStatus::Pending), 1);

    manager
        .update_intent_status("0x1234567890abcdef", IntentStatus::Locked)
        .unwrap();
    assert_eq!(manager.get_intent_count_by_status(IntentStatus::Locked), 1);
    assert_eq!(manager.get_intent_count_by_status(IntentStatus::Pending), 0);

    manager
        .update_intent_status("0x1234567890abcdef", IntentStatus::Fulfilling)
        .unwrap();
    assert_eq!(
        manager.get_intent_count_by_status(IntentStatus::Fulfilling),
        1
    );

    manager
        .update_intent_status("0x1234567890abcdef", IntentStatus::Fulfilled)
        .unwrap();
    assert_eq!(
        manager.get_intent_count_by_status(IntentStatus::Fulfilled),
        1
    );
}

#[test]
fn test_multiple_intents() {
    let mut manager = IntentManager::new();

    // Add multiple intents
    for i in 0..5 {
        let intent_data = IntentData {
            intent_id: format!("0x{:016x}", i),
            user_address: Address::from_str("0x1234567890123456789012345678901234567890").unwrap(),
            btc_destination: format!("tb1qexample{}", i),
            lane_btc_amount: U256::from(1000000u64 + i * 100000),
            fee: U256::from(10000u64),
        };

        manager.add_intent(intent_data).unwrap();
    }

    assert_eq!(manager.get_intent_count(), 5);
    assert_eq!(manager.get_intent_count_by_status(IntentStatus::Pending), 5);

    // Update some intents
    manager
        .update_intent_status("0x0000000000000000", IntentStatus::Locked)
        .unwrap();
    manager
        .update_intent_status("0x0000000000000001", IntentStatus::Fulfilled)
        .unwrap();

    assert_eq!(manager.get_intent_count_by_status(IntentStatus::Pending), 3);
    assert_eq!(manager.get_intent_count_by_status(IntentStatus::Locked), 1);
    assert_eq!(
        manager.get_intent_count_by_status(IntentStatus::Fulfilled),
        1
    );
}
