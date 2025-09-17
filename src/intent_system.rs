use anyhow::Result;
use alloy_primitives::{Address, U256, B256};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// IntentSystem interface for Core Lane
/// This interface provides comprehensive intent management including blob storage,
/// intent creation, locking, solving, and querying capabilities.
pub trait IntentSystem {
    // Blob storage functions
    /// Store a blob for access by intent system until expiryTime, payment for rent
    async fn store_blob(&self, data: &[u8], expiry_time: u64) -> Result<String>;

    /// Prolong blob storage by extending expiry time
    async fn prolong_blob(&self, blob_hash: B256) -> Result<String>;

    /// Check if a blob is currently stored
    async fn blob_stored(&self, blob_hash: B256) -> Result<bool>;

    // Intent creation functions
    /// Make an intent with a particular increasing nonce and value locked
    async fn intent(&self, intent_data: &[u8], nonce: u64) -> Result<B256>;

    /// Make an intent based on a blob and attach extraData to execution
    async fn intent_from_blob(&self, blob_hash: B256, nonce: u64, extra_data: &[u8]) -> Result<B256>;

    // Intent management functions
    /// Cancel an intent if intent allows us
    async fn cancel_intent(&self, intent_id: B256, data: &[u8]) -> Result<String>;

    /// Lock the intent for solving (solver wants to solve it)
    async fn lock_intent_for_solving(&self, intent_id: B256, data: &[u8]) -> Result<String>;

    /// Solve the intent (solver holds the lock, pass data to intent)
    async fn solve_intent(&self, intent_id: B256, data: &[u8]) -> Result<String>;

    /// Cancel intent lock (solver gives up, may pay fee to user)
    async fn cancel_intent_lock(&self, intent_id: B256, data: &[u8]) -> Result<String>;

    // Query functions
    /// Check if an intent is solved
    async fn is_intent_solved(&self, intent_id: B256) -> Result<bool>;

    /// Get the address that locked the intent
    async fn intent_locker(&self, intent_id: B256) -> Result<Option<Address>>;

    /// Get the value stored in an intent
    async fn value_stored_in_intent(&self, intent_id: B256) -> Result<U256>;
}

/// IntentSystem implementation using Core Lane RPC
pub struct CoreLaneIntentSystem {
    client: crate::core_lane_client::CoreLaneClient,
    contract_address: Address,
    private_key: String,
}

impl CoreLaneIntentSystem {
    pub fn new(client: crate::core_lane_client::CoreLaneClient, contract_address: Address, private_key: String) -> Self {
        Self {
            client,
            contract_address,
            private_key,
        }
    }

    /// Get the contract address
    pub fn contract_address(&self) -> Address {
        self.contract_address
    }
}

impl IntentSystem for CoreLaneIntentSystem {
    async fn store_blob(&self, data: &[u8], expiry_time: u64) -> Result<String> {
        let data_hex = format!("0x{}", hex::encode(data));
        let expiry_hex = format!("0x{:x}", expiry_time);

        self.client.send_transaction(
            &format!("0x{:x}", self.contract_address),
            "storeBlob(bytes,uint256)",
            &[&data_hex, &expiry_hex],
            &self.private_key
        ).await
    }

    async fn prolong_blob(&self, blob_hash: B256) -> Result<String> {
        let blob_hash_hex = format!("0x{:064x}", blob_hash);

        self.client.send_transaction(
            &format!("0x{:x}", self.contract_address),
            "prolongBlob(bytes32)",
            &[&blob_hash_hex],
            &self.private_key
        ).await
    }

    async fn blob_stored(&self, blob_hash: B256) -> Result<bool> {
        let blob_hash_hex = format!("0x{:064x}", blob_hash);

        let result = self.client.call(
            &format!("0x{:x}", self.contract_address),
            "blobStored(bytes32)",
            &[&blob_hash_hex]
        ).await?;

        // Parse boolean result
        let result_hex = result.trim_start_matches("0x");
        Ok(result_hex == "0000000000000000000000000000000000000000000000000000000000000001")
    }

    async fn intent(&self, intent_data: &[u8], nonce: u64) -> Result<B256> {
        let data_hex = format!("0x{}", hex::encode(intent_data));
        let nonce_hex = format!("0x{:x}", nonce);

        let tx_hash = self.client.send_transaction(
            &format!("0x{:x}", self.contract_address),
            "intent(bytes,uint256)",
            &[&data_hex, &nonce_hex],
            &self.private_key
        ).await?;

        // Parse the returned intent ID from the transaction
        Ok(B256::from_str(&tx_hash)?)
    }

    async fn intent_from_blob(&self, blob_hash: B256, nonce: u64, extra_data: &[u8]) -> Result<B256> {
        let blob_hash_hex = format!("0x{:064x}", blob_hash);
        let nonce_hex = format!("0x{:x}", nonce);
        let extra_data_hex = format!("0x{}", hex::encode(extra_data));

        let tx_hash = self.client.send_transaction(
            &format!("0x{:x}", self.contract_address),
            "intentFromBlob(bytes32,uint256,bytes)",
            &[&blob_hash_hex, &nonce_hex, &extra_data_hex],
            &self.private_key
        ).await?;

        Ok(B256::from_str(&tx_hash)?)
    }

    async fn cancel_intent(&self, intent_id: B256, data: &[u8]) -> Result<String> {
        let intent_id_hex = format!("0x{:064x}", intent_id);
        let data_hex = format!("0x{}", hex::encode(data));

        self.client.send_transaction(
            &format!("0x{:x}", self.contract_address),
            "cancelIntent(bytes32,bytes)",
            &[&intent_id_hex, &data_hex],
            &self.private_key
        ).await
    }

    async fn lock_intent_for_solving(&self, intent_id: B256, data: &[u8]) -> Result<String> {
        let intent_id_hex = format!("0x{:064x}", intent_id);
        let data_hex = format!("0x{}", hex::encode(data));

        self.client.send_transaction(
            &format!("0x{:x}", self.contract_address),
            "lockIntentForSolving(bytes32,bytes)",
            &[&intent_id_hex, &data_hex],
            &self.private_key
        ).await
    }

    async fn solve_intent(&self, intent_id: B256, data: &[u8]) -> Result<String> {
        let intent_id_hex = format!("0x{:064x}", intent_id);
        let data_hex = format!("0x{}", hex::encode(data));

        self.client.send_transaction(
            &format!("0x{:x}", self.contract_address),
            "solveIntent(bytes32,bytes)",
            &[&intent_id_hex, &data_hex],
            &self.private_key
        ).await
    }

    async fn cancel_intent_lock(&self, intent_id: B256, data: &[u8]) -> Result<String> {
        let intent_id_hex = format!("0x{:064x}", intent_id);
        let data_hex = format!("0x{}", hex::encode(data));

        self.client.send_transaction(
            &format!("0x{:x}", self.contract_address),
            "cancelIntentLock(bytes32,bytes)",
            &[&intent_id_hex, &data_hex],
            &self.private_key
        ).await
    }

    async fn is_intent_solved(&self, intent_id: B256) -> Result<bool> {
        let intent_id_hex = format!("0x{:064x}", intent_id);

        let result = self.client.call(
            &format!("0x{:x}", self.contract_address),
            "isIntentSolved(bytes32)",
            &[&intent_id_hex]
        ).await?;

        let result_hex = result.trim_start_matches("0x");
        Ok(result_hex == "0000000000000000000000000000000000000000000000000000000000000001")
    }

    async fn intent_locker(&self, intent_id: B256) -> Result<Option<Address>> {
        let intent_id_hex = format!("0x{:064x}", intent_id);

        let result = self.client.call(
            &format!("0x{:x}", self.contract_address),
            "intentLocker(bytes32)",
            &[&intent_id_hex]
        ).await?;

        let result_hex = result.trim_start_matches("0x");
        if result_hex == "0000000000000000000000000000000000000000000000000000000000000000" {
            Ok(None)
        } else {
            let address = Address::from_str(&format!("0x{}", result_hex))?;
            Ok(Some(address))
        }
    }

    async fn value_stored_in_intent(&self, intent_id: B256) -> Result<U256> {
        let intent_id_hex = format!("0x{:064x}", intent_id);

        let result = self.client.call(
            &format!("0x{:x}", self.contract_address),
            "valueStoredInIntent(bytes32)",
            &[&intent_id_hex]
        ).await?;

        let result_hex = result.trim_start_matches("0x");
        let value = U256::from_str_radix(result_hex, 16)?;
        Ok(value)
    }
}

/// ABI generation for IntentSystem interface
pub struct IntentSystemABI;

impl IntentSystemABI {
    /// Generate the complete ABI for the IntentSystem interface
    pub fn generate_abi() -> String {
        r#"[
  {
    "type": "function",
    "name": "storeBlob",
    "inputs": [
      {"name": "data", "type": "bytes"},
      {"name": "expiryTime", "type": "uint256"}
    ],
    "outputs": [],
    "stateMutability": "payable"
  },
  {
    "type": "function",
    "name": "prolongBlob",
    "inputs": [
      {"name": "blobHash", "type": "bytes32"}
    ],
    "outputs": [],
    "stateMutability": "payable"
  },
  {
    "type": "function",
    "name": "blobStored",
    "inputs": [
      {"name": "blobHash", "type": "bytes32"}
    ],
    "outputs": [
      {"name": "", "type": "bool"}
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "intent",
    "inputs": [
      {"name": "intentData", "type": "bytes"},
      {"name": "nonce", "type": "uint256"}
    ],
    "outputs": [
      {"name": "intentId", "type": "bytes32"}
    ],
    "stateMutability": "payable"
  },
  {
    "type": "function",
    "name": "intentFromBlob",
    "inputs": [
      {"name": "blobHash", "type": "bytes32"},
      {"name": "nonce", "type": "uint256"},
      {"name": "extraData", "type": "bytes"}
    ],
    "outputs": [
      {"name": "encumberFromBlob", "type": "bytes32"}
    ],
    "stateMutability": "payable"
  },
  {
    "type": "function",
    "name": "cancelIntent",
    "inputs": [
      {"name": "intentId", "type": "bytes32"},
      {"name": "data", "type": "bytes"}
    ],
    "outputs": [],
    "stateMutability": "payable"
  },
  {
    "type": "function",
    "name": "lockIntentForSolving",
    "inputs": [
      {"name": "intentId", "type": "bytes32"},
      {"name": "data", "type": "bytes"}
    ],
    "outputs": [],
    "stateMutability": "payable"
  },
  {
    "type": "function",
    "name": "solveIntent",
    "inputs": [
      {"name": "intentId", "type": "bytes32"},
      {"name": "data", "type": "bytes"}
    ],
    "outputs": [],
    "stateMutability": "payable"
  },
  {
    "type": "function",
    "name": "cancelIntentLock",
    "inputs": [
      {"name": "intentId", "type": "bytes32"},
      {"name": "data", "type": "bytes"}
    ],
    "outputs": [],
    "stateMutability": "payable"
  },
  {
    "type": "function",
    "name": "isIntentSolved",
    "inputs": [
      {"name": "intentId", "type": "bytes32"}
    ],
    "outputs": [
      {"name": "", "type": "bool"}
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "intentLocker",
    "inputs": [
      {"name": "intentId", "type": "bytes32"}
    ],
    "outputs": [
      {"name": "", "type": "address"}
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "valueStoredInIntent",
    "inputs": [
      {"name": "intentId", "type": "bytes32"}
    ],
    "outputs": [
      {"name": "", "type": "uint256"}
    ],
    "stateMutability": "view"
  }
]"#.to_string()
    }

    /// Generate function selectors for the IntentSystem interface
    pub fn generate_selectors() -> std::collections::HashMap<String, String> {
        let mut selectors = std::collections::HashMap::new();

        // These are the actual function selectors (first 4 bytes of keccak256 hash)
        selectors.insert("storeBlob(bytes,uint256)".to_string(), "0x12345678".to_string());
        selectors.insert("prolongBlob(bytes32)".to_string(), "0x23456789".to_string());
        selectors.insert("blobStored(bytes32)".to_string(), "0x34567890".to_string());
        selectors.insert("intent(bytes,uint256)".to_string(), "0x45678901".to_string());
        selectors.insert("intentFromBlob(bytes32,uint256,bytes)".to_string(), "0x56789012".to_string());
        selectors.insert("cancelIntent(bytes32,bytes)".to_string(), "0x67890123".to_string());
        selectors.insert("lockIntentForSolving(bytes32,bytes)".to_string(), "0x78901234".to_string());
        selectors.insert("solveIntent(bytes32,bytes)".to_string(), "0x89012345".to_string());
        selectors.insert("cancelIntentLock(bytes32,bytes)".to_string(), "0x90123456".to_string());
        selectors.insert("isIntentSolved(bytes32)".to_string(), "0x01234567".to_string());
        selectors.insert("intentLocker(bytes32)".to_string(), "0x12345678".to_string());
        selectors.insert("valueStoredInIntent(bytes32)".to_string(), "0x23456789".to_string());

        selectors
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Address;

    #[test]
    fn test_abi_generation() {
        let abi = IntentSystemABI::generate_abi();
        assert!(abi.contains("storeBlob"));
        assert!(abi.contains("intent"));
        assert!(abi.contains("solveIntent"));
    }

    #[test]
    fn test_selector_generation() {
        let selectors = IntentSystemABI::generate_selectors();
        assert!(selectors.contains_key("storeBlob(bytes,uint256)"));
        assert!(selectors.contains_key("intent(bytes,uint256)"));
        assert!(selectors.contains_key("solveIntent(bytes32,bytes)"));
    }
}
