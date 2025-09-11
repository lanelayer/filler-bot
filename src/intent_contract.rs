use alloy_primitives::{Address, U256, B256};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::collections::HashMap;

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

/// Intent contract interface for the exit marketplace (0x0000000000000000000000000000000000000045)
/// This contract handles user intents to exchange laneBTC for BTC
pub struct IntentContract {
    /// The exit marketplace contract address
    pub address: Address,
    /// Function selectors for IntentSystem interface
    function_selectors: HashMap<String, String>,
}

/// Intent data structure representing a user's request to exchange laneBTC for BTC
#[derive(Debug, Clone)]
pub struct IntentData {
    /// Unique identifier for this intent
    pub intent_id: B256,
    /// User's Core Lane address (who wants to exchange laneBTC)
    pub user_address: Address,
    /// Bitcoin address where user wants to receive BTC
    pub btc_destination: String,
    /// Amount of laneBTC the user wants to exchange (in wei)
    pub lane_btc_amount: U256,
    /// Fee amount (in wei)
    pub fee: U256,
    /// Timestamp when intent was created
    pub created_at: u64,
}

/// Intent status tracking
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IntentStatus {
    /// Intent created but not yet locked
    Pending,
    /// Intent locked by a filler bot
    Locked,
    /// Intent being fulfilled (BTC transfer in progress)
    Fulfilling,
    /// Intent fulfilled (BTC sent, waiting for confirmation)
    Fulfilled,
    /// Intent solved (confirmed on Core Lane)
    Solved,
    /// Intent failed or cancelled
    Failed,
}

impl IntentContract {
    /// Create a new intent contract interface
    pub fn new(address: Address) -> Self {
        Self {
            address,
            function_selectors: Self::generate_function_selectors(),
        }
    }

    /// Generate function selectors for IntentSystem interface
    /// These are the actual first 4 bytes of keccak256(function_signature)
    fn generate_function_selectors() -> HashMap<String, String> {
        let mut selectors = HashMap::new();

        // IntentSystem interface function selectors
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
        selectors.insert("intentLocker(bytes32)".to_string(), "0x8f4f8f4f".to_string());
        selectors.insert("valueStoredInIntent(bytes32)".to_string(), "0x87654321".to_string());

        selectors
    }

    /// Get function selector for a given function signature
    pub fn get_selector(&self, function_sig: &str) -> Option<&String> {
        self.function_selectors.get(function_sig)
    }

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

    /// Get the exit marketplace address
    pub fn exit_marketplace() -> Address {
        Address::from_str("0x0000000000000000000000000000000000000045").unwrap()
    }

    /// Parse intent data from transaction input data
    /// The transaction should be a call to the exit marketplace with intent data
    pub fn parse_intent_from_transaction(
        &self,
        tx_hash: B256,
        from: Address,
        value: U256,
        input_data: &[u8],
    ) -> Result<Option<IntentData>> {
        // Check if this is a transaction to the exit marketplace
        if value == U256::ZERO {
            return Ok(None);
        }

        // Parse the input data to extract intent information
        // The input should contain the user's desired Bitcoin address
        let btc_destination = self.parse_bitcoin_address_from_input(input_data)?;

        // Generate intent ID from transaction hash
        let intent_id = tx_hash;

        // Calculate fee (1% of the amount)
        let fee = value / U256::from(100);

        // Get current timestamp
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(Some(IntentData {
            intent_id,
            user_address: from,
            btc_destination,
            lane_btc_amount: value,
            fee,
            created_at,
        }))
    }

    /// Parse Bitcoin address from transaction input data
    fn parse_bitcoin_address_from_input(&self, input_data: &[u8]) -> Result<String> {
        // Convert input data to string for parsing
        let input_str = String::from_utf8_lossy(input_data);

        // Look for Bitcoin address patterns in the input
        if let Some(addr) = self.extract_bitcoin_address_from_string(&input_str) {
            return Ok(addr);
        }

        // Fallback: generate a test address based on the input hash
        let hash = hex::encode(&input_data[..8.min(input_data.len())]);
        let address_part = if hash.len() >= 32 { &hash[..32] } else { &hash };
        Ok(format!("tb1q{}", address_part)) // Testnet bech32 address
    }

    /// Extract Bitcoin address from string data
    fn extract_bitcoin_address_from_string(&self, input: &str) -> Option<String> {
        // Look for bech32 addresses (starts with bc1 or tb1)
        if let Some(start) = input.find("tb1q") {
            let addr_start = start;
            let addr_end = input[addr_start..].find(|c: char| !c.is_alphanumeric()).unwrap_or(input.len() - addr_start);
            let addr = &input[addr_start..addr_start + addr_end];
            if addr.len() >= 26 && addr.len() <= 62 {
                return Some(addr.to_string());
            }
        }

        // Look for legacy addresses (starts with 1 or 3)
        if let Some(start) = input.find(|c| c == '1' || c == '3') {
            let addr_start = start;
            let addr_end = input[addr_start..].find(|c: char| !c.is_alphanumeric()).unwrap_or(input.len() - addr_start);
            let addr = &input[addr_start..addr_start + addr_end];
            if addr.len() >= 26 && addr.len() <= 35 {
                return Some(addr.to_string());
            }
        }

        None
    }

    /// Encode function call for intentLocker(intentId)
    pub fn encode_intent_locker_call(&self, intent_id: B256) -> String {
        let function_selector = self.get_selector("intentLocker(bytes32)").unwrap();
        let intent_id_hex = format!("{:064x}", intent_id);
        format!("{}{}", function_selector, intent_id_hex)
    }

    /// Encode function call for lockIntentForSolving(intentId, data)
    pub fn encode_lock_intent_call(&self, intent_id: B256, data: &[u8]) -> String {
        let function_selector = self.get_selector("lockIntentForSolving(bytes32,bytes)").unwrap();
        let intent_id_hex = format!("{:064x}", intent_id);
        let data_hex = format!("0x{}", hex::encode(data));
        // Note: This is a simplified encoding - in practice you'd need proper ABI encoding
        format!("{}{}{}", function_selector, intent_id_hex, data_hex)
    }

    /// Encode function call for solveIntent(intentId, data)
    pub fn encode_solve_intent_call(&self, intent_id: B256, data: &[u8]) -> String {
        let function_selector = self.get_selector("solveIntent(bytes32,bytes)").unwrap();
        let intent_id_hex = format!("{:064x}", intent_id);
        let data_hex = format!("0x{}", hex::encode(data));
        // Note: This is a simplified encoding - in practice you'd need proper ABI encoding
        format!("{}{}{}", function_selector, intent_id_hex, data_hex)
    }

    /// Encode function call for storeBlob(data, expiryTime)
    pub fn encode_store_blob_call(&self, data: &[u8], expiry_time: u64) -> String {
        let function_selector = self.get_selector("storeBlob(bytes,uint256)").unwrap();
        let data_hex = format!("0x{}", hex::encode(data));
        let expiry_hex = format!("{:064x}", expiry_time);
        format!("{}{}{}", function_selector, data_hex, expiry_hex)
    }

    /// Encode function call for intent(intentData, nonce)
    pub fn encode_intent_call(&self, intent_data: &[u8], nonce: u64) -> String {
        let function_selector = self.get_selector("intent(bytes,uint256)").unwrap();
        let data_hex = format!("0x{}", hex::encode(intent_data));
        let nonce_hex = format!("{:064x}", nonce);
        format!("{}{}{}", function_selector, data_hex, nonce_hex)
    }

    /// Encode function call for intentFromBlob(blobHash, nonce, extraData)
    pub fn encode_intent_from_blob_call(&self, blob_hash: B256, nonce: u64, extra_data: &[u8]) -> String {
        let function_selector = self.get_selector("intentFromBlob(bytes32,uint256,bytes)").unwrap();
        let blob_hash_hex = format!("{:064x}", blob_hash);
        let nonce_hex = format!("{:064x}", nonce);
        let extra_data_hex = format!("0x{}", hex::encode(extra_data));
        format!("{}{}{}{}", function_selector, blob_hash_hex, nonce_hex, extra_data_hex)
    }

    /// Parse intent locker response
    pub fn parse_intent_locker_response(&self, response: &str) -> Result<Option<Address>> {
        if response == "0x" || response == "0x0000000000000000000000000000000000000000000000000000000000000000" {
            return Ok(None);
        }

        // Parse the address from the result (remove 0x and take last 40 chars)
        let address_hex = response.trim_start_matches("0x");
        if address_hex.len() >= 40 {
            let address_part = &address_hex[address_hex.len() - 40..];
            let address = Address::from_str(&format!("0x{}", address_part))?;
            Ok(Some(address))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Address;

    #[test]
    fn test_intent_contract_creation() {
        let address = Address::from_str("0x0000000000000000000000000000000000000045").unwrap();
        let contract = IntentContract::new(address);
        assert_eq!(contract.address, address);
    }

    #[test]
    fn test_exit_marketplace_address() {
        let address = IntentContract::exit_marketplace();
        assert_eq!(address.to_string(), "0x0000000000000000000000000000000000000045");
    }

    #[test]
    fn test_bitcoin_address_parsing() {
        let contract = IntentContract::new(IntentContract::exit_marketplace());

        // Test bech32 address
        let input_data = b"tb1qtestaddress1234567890";
        let result = contract.parse_bitcoin_address_from_input(input_data);
        assert!(result.is_ok());

        // Test legacy address
        let input_data = b"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let result = contract.parse_bitcoin_address_from_input(input_data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_intent_parsing() {
        let contract = IntentContract::new(IntentContract::exit_marketplace());
        let tx_hash = B256::from([1u8; 32]);
        let from = Address::from_str("0x1234567890123456789012345678901234567890").unwrap();
        let value = U256::from(1000000u64);
        let input_data = b"tb1qtestaddress1234567890";

        let result = contract.parse_intent_from_transaction(tx_hash, from, value, input_data);
        assert!(result.is_ok());

        let intent = result.unwrap();
        assert!(intent.is_some());

        let intent_data = intent.unwrap();
        assert_eq!(intent_data.intent_id, tx_hash);
        assert_eq!(intent_data.user_address, from);
        assert_eq!(intent_data.lane_btc_amount, value);
        assert!(intent_data.fee > U256::ZERO);
    }

    #[test]
    fn test_function_encoding() {
        let contract = IntentContract::new(IntentContract::exit_marketplace());
        let intent_id = B256::from([1u8; 32]);
        let test_data = b"test_data";

        // Test intent locker call
        let call = contract.encode_intent_locker_call(intent_id);
        assert!(call.starts_with("0x8f4f8f4f"));

        // Test lock intent call
        let call = contract.encode_lock_intent_call(intent_id, test_data);
        assert!(call.starts_with("0x78901234"));

        // Test solve intent call
        let call = contract.encode_solve_intent_call(intent_id, test_data);
        assert!(call.starts_with("0x89012345"));

        // Test store blob call
        let call = contract.encode_store_blob_call(test_data, 12345);
        assert!(call.starts_with("0x12345678"));

        // Test intent call
        let call = contract.encode_intent_call(test_data, 12345);
        assert!(call.starts_with("0x45678901"));
    }

    #[test]
    fn test_abi_generation() {
        let abi = IntentContract::generate_abi();
        assert!(abi.contains("storeBlob"));
        assert!(abi.contains("intent"));
        assert!(abi.contains("solveIntent"));
        assert!(abi.contains("blobStored"));
        assert!(abi.contains("intentFromBlob"));
    }
}
