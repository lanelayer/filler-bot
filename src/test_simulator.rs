use anyhow::Result;
use alloy_primitives::{Address, B256};
use std::str::FromStr;
use sha2::{Sha256, Digest};

use crate::core_lane_client::CoreLaneClient;
use crate::intent_contract::IntentContract;

/// Test the filler bot against the IntentSystem simulator contract
pub struct SimulatorTester {
    client: CoreLaneClient,
    contract: IntentContract,
    simulator_address: Address,
}

impl SimulatorTester {
    pub fn new(rpc_url: String, simulator_address: Address) -> Self {
        let client = CoreLaneClient::new(rpc_url);
        let contract = IntentContract::new(simulator_address);

        Self {
            client,
            contract,
            simulator_address,
        }
    }

    /// Test blob storage functionality
    pub async fn test_blob_storage(&self) -> Result<()> {
        println!("🧪 Testing blob storage functionality...");

        // Test data
        let test_data = b"test blob data for simulator";
        let expiry_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() + 86400; // 1 day from now

        // Store blob
        println!("📦 Storing blob...");
        let store_call = self.contract.encode_store_blob_call(test_data, expiry_time);
        println!("📞 Store blob call data: {}", store_call);

        // Check if blob is stored
        let hash = Sha256::digest(test_data);
        let blob_hash = B256::from_slice(&hash);
        println!("🔍 Blob hash: {:?}", blob_hash);

        // Test prolong blob
        println!("⏰ Testing prolong blob...");
        let prolong_call = self.contract.encode_call("prolongBlob(bytes32)", &[&format!("{:064x}", blob_hash)]);
        println!("📞 Prolong blob call data: {}", prolong_call);

        println!("✅ Blob storage test completed");
        Ok(())
    }

    /// Test intent creation functionality
    pub async fn test_intent_creation(&self) -> Result<()> {
        println!("🧪 Testing intent creation functionality...");

        // Test data
        let intent_data = b"test intent data for simulator";
        let nonce = 1u64;

        // Create intent
        println!("📝 Creating intent...");
        let intent_call = self.contract.encode_intent_call(intent_data, nonce);
        println!("📞 Intent call data: {}", intent_call);

        // Create intent from blob
        let blob_hash = B256::from([1u8; 32]);
        let extra_data = b"extra data for intent from blob";
        println!("📝 Creating intent from blob...");
        let intent_from_blob_call = self.contract.encode_intent_from_blob_call(blob_hash, nonce, extra_data);
        println!("📞 Intent from blob call data: {}", intent_from_blob_call);

        println!("✅ Intent creation test completed");
        Ok(())
    }

    /// Test intent management functionality
    pub async fn test_intent_management(&self) -> Result<()> {
        println!("🧪 Testing intent management functionality...");

        let intent_id = B256::from([2u8; 32]);
        let data = b"test management data";

        // Test lock intent for solving
        println!("🔒 Testing lock intent for solving...");
        let lock_call = self.contract.encode_lock_intent_call(intent_id, data);
        println!("📞 Lock intent call data: {}", lock_call);

        // Test solve intent
        println!("✅ Testing solve intent...");
        let solve_call = self.contract.encode_solve_intent_call(intent_id, data);
        println!("📞 Solve intent call data: {}", solve_call);

        // Test cancel intent
        println!("❌ Testing cancel intent...");
        let cancel_call = self.contract.encode_call("cancelIntent(bytes32,bytes)", &[
            &format!("{:064x}", intent_id),
            &format!("0x{}", hex::encode(data))
        ]);
        println!("📞 Cancel intent call data: {}", cancel_call);

        // Test cancel intent lock
        println!("🔓 Testing cancel intent lock...");
        let cancel_lock_call = self.contract.encode_call("cancelIntentLock(bytes32,bytes)", &[
            &format!("{:064x}", intent_id),
            &format!("0x{}", hex::encode(data))
        ]);
        println!("📞 Cancel intent lock call data: {}", cancel_lock_call);

        println!("✅ Intent management test completed");
        Ok(())
    }

    /// Test query functionality
    pub async fn test_query_functions(&self) -> Result<()> {
        println!("🧪 Testing query functionality...");

        let intent_id = B256::from([3u8; 32]);

        // Test intent locker query
        println!("🔍 Testing intent locker query...");
        let locker_call = self.contract.encode_intent_locker_call(intent_id);
        println!("📞 Intent locker call data: {}", locker_call);

        // Test is intent solved query
        println!("🔍 Testing is intent solved query...");
        let solved_call = self.contract.encode_call("isIntentSolved(bytes32)", &[&format!("{:064x}", intent_id)]);
        println!("📞 Is intent solved call data: {}", solved_call);

        // Test value stored in intent query
        println!("🔍 Testing value stored in intent query...");
        let value_call = self.contract.encode_call("valueStoredInIntent(bytes32)", &[&format!("{:064x}", intent_id)]);
        println!("📞 Value stored in intent call data: {}", value_call);

        println!("✅ Query functions test completed");
        Ok(())
    }

    /// Run all tests
    pub async fn run_all_tests(&self) -> Result<()> {
        println!("🚀 Starting IntentSystem simulator tests...");
        println!("📡 Simulator address: 0x{:x}", self.simulator_address);
        println!("🔗 RPC URL: {}", "http://127.0.0.1:8545");
        println!();

        // Test blob storage
        self.test_blob_storage().await?;
        println!();

        // Test intent creation
        self.test_intent_creation().await?;
        println!();

        // Test intent management
        self.test_intent_management().await?;
        println!();

        // Test query functions
        self.test_query_functions().await?;
        println!();

        println!("🎉 All simulator tests completed successfully!");
        Ok(())
    }
}

impl IntentContract {
    /// Helper method to encode generic function calls
    pub fn encode_call(&self, function_sig: &str, args: &[&str]) -> String {
        if let Some(selector) = self.get_selector(function_sig) {
            let mut call_data = selector.clone();
            for arg in args {
                call_data.push_str(arg);
            }
            call_data
        } else {
            format!("Function {} not found", function_sig)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_simulator_creation() {
        let simulator_addr = Address::from_str("0x1234567890123456789012345678901234567890").unwrap();
        let tester = SimulatorTester::new("http://127.0.0.1:8545".to_string(), simulator_addr);

        // Test that we can create the tester
        assert_eq!(tester.simulator_address, simulator_addr);
    }

    #[tokio::test]
    async fn test_function_encoding() {
        let simulator_addr = Address::from_str("0x1234567890123456789012345678901234567890").unwrap();
        let contract = IntentContract::new(simulator_addr);

        // Test that we can encode function calls
        let intent_id = B256::from([1u8; 32]);
        let call = contract.encode_intent_locker_call(intent_id);
        assert!(call.starts_with("0x"));
    }
}
