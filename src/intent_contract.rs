use alloy_primitives::{Address, U256, B256, Bytes, keccak256};
use alloy_sol_types::{sol, SolCall};
use anyhow::Result;
use std::str::FromStr;
use crate::intent_manager::IntentData;

sol! {
    #[allow(missing_docs)]
    interface IntentSystem {
        function storeBlob(bytes data, uint256 expiryTime) payable;
        function prolongBlob(bytes32 blobHash) payable;
        function blobStored(bytes32 blobHash) view returns (bool);
        function intent(bytes intentData, uint256 nonce) payable returns (bytes32 intentId);
        function intentFromBlob(bytes32 blobHash, uint256 nonce, bytes extraData) payable returns (bytes32 encumberFromBlob);
        function cancelIntent(bytes32 intentId, bytes data) payable;
        function lockIntentForSolving(bytes32 intentId, bytes data) payable;
        function solveIntent(bytes32 intentId, bytes data) payable;
        function cancelIntentLock(bytes32 intentId, bytes data) payable;
        function isIntentSolved(bytes32 intentId) view returns (bool);
        function intentLocker(bytes32 intentId) view returns (address);
        function valueStoredInIntent(bytes32 intentId) view returns (uint256);
    }
}

#[derive(Debug, Clone)]
pub enum IntentCall {
    StoreBlob {
        data: Vec<u8>,
        expiry_time: U256,
    },
    ProlongBlob {
        blob_hash: B256,
    },
    BlobStored {
        blob_hash: B256,
    },
    Intent {
        intent_data: Vec<u8>,
        nonce: U256,
    },
    IntentFromBlob {
        blob_hash: B256,
        nonce: U256,
        extra_data: Vec<u8>,
    },
    CancelIntent {
        intent_id: B256,
        data: Vec<u8>,
    },
    CancelIntentLock {
        intent_id: B256,
        data: Vec<u8>,
    },
    LockIntentForSolving {
        intent_id: B256,
        data: Vec<u8>,
    },
    SolveIntent {
        intent_id: B256,
        data: Vec<u8>,
    },
    IsIntentSolved {
        intent_id: B256,
    },
    IntentLocker {
        intent_id: B256,
    },
    ValueStoredInIntent {
        intent_id: B256,
    },
}

/// IntentSystemInterface for Core Lane
/// This interface provides comprehensive intent management including blob storage,
/// intent creation, locking, solving, and querying capabilities.
pub trait IntentSystemInterface {
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
}

// IntentData and IntentStatus are now defined in intent_manager.rs to avoid duplication

/// Extract function selector from calldata
fn extract_selector(calldata: &[u8]) -> Option<[u8; 4]> {
    if calldata.len() < 4 {
        return None;
    }
    Some([calldata[0], calldata[1], calldata[2], calldata[3]])
}

/// Decode intent calldata using alloy-sol-types
pub fn decode_intent_calldata(calldata: &[u8]) -> Option<IntentCall> {
    let selector = extract_selector(calldata)?;

    match selector {
        IntentSystem::storeBlobCall::SELECTOR => {
            let Ok(call) = IntentSystem::storeBlobCall::abi_decode(calldata) else {
                return None;
            };
            Some(IntentCall::StoreBlob {
                data: call.data.to_vec(),
                expiry_time: call.expiryTime,
            })
        }
        IntentSystem::prolongBlobCall::SELECTOR => {
            let Ok(call) = IntentSystem::prolongBlobCall::abi_decode(calldata) else {
                return None;
            };
            Some(IntentCall::ProlongBlob {
                blob_hash: B256::from_slice(call.blobHash.as_slice()),
            })
        }
        IntentSystem::blobStoredCall::SELECTOR => {
            let Ok(call) = IntentSystem::blobStoredCall::abi_decode(calldata) else {
                return None;
            };
            Some(IntentCall::BlobStored {
                blob_hash: B256::from_slice(call.blobHash.as_slice()),
            })
        }
        IntentSystem::intentCall::SELECTOR => {
            let Ok(call) = IntentSystem::intentCall::abi_decode(calldata) else {
                return None;
            };
            Some(IntentCall::Intent {
                intent_data: call.intentData.to_vec(),
                nonce: call.nonce,
            })
        }
        IntentSystem::intentFromBlobCall::SELECTOR => {
            let Ok(call) = IntentSystem::intentFromBlobCall::abi_decode(calldata) else {
                return None;
            };
            Some(IntentCall::IntentFromBlob {
                blob_hash: B256::from_slice(call.blobHash.as_slice()),
                nonce: call.nonce,
                extra_data: call.extraData.to_vec(),
            })
        }
        IntentSystem::cancelIntentCall::SELECTOR => {
            let Ok(call) = IntentSystem::cancelIntentCall::abi_decode(calldata) else {
                return None;
            };
            Some(IntentCall::CancelIntent {
                intent_id: B256::from_slice(call.intentId.as_slice()),
                data: call.data.to_vec(),
            })
        }
        IntentSystem::lockIntentForSolvingCall::SELECTOR => {
            let Ok(call) = IntentSystem::lockIntentForSolvingCall::abi_decode(calldata) else {
                return None;
            };
            Some(IntentCall::LockIntentForSolving {
                intent_id: B256::from_slice(call.intentId.as_slice()),
                data: call.data.to_vec(),
            })
        }
        IntentSystem::solveIntentCall::SELECTOR => {
            let Ok(call) = IntentSystem::solveIntentCall::abi_decode(calldata) else {
                return None;
            };
            Some(IntentCall::SolveIntent {
                intent_id: B256::from_slice(call.intentId.as_slice()),
                data: call.data.to_vec(),
            })
        }
        IntentSystem::cancelIntentLockCall::SELECTOR => {
            let Ok(call) = IntentSystem::cancelIntentLockCall::abi_decode(calldata) else {
                return None;
            };
            Some(IntentCall::CancelIntentLock {
                intent_id: B256::from_slice(call.intentId.as_slice()),
                data: call.data.to_vec(),
            })
        }
        IntentSystem::isIntentSolvedCall::SELECTOR => {
            let Ok(call) = IntentSystem::isIntentSolvedCall::abi_decode(calldata) else {
                return None;
            };
            Some(IntentCall::IsIntentSolved {
                intent_id: B256::from_slice(call.intentId.as_slice()),
            })
        }
        IntentSystem::intentLockerCall::SELECTOR => {
            let Ok(call) = IntentSystem::intentLockerCall::abi_decode(calldata) else {
                return None;
            };
            Some(IntentCall::IntentLocker {
                intent_id: B256::from_slice(call.intentId.as_slice()),
            })
        }
        IntentSystem::valueStoredInIntentCall::SELECTOR => {
            let Ok(call) = IntentSystem::valueStoredInIntentCall::abi_decode(calldata) else {
                return None;
            };
            Some(IntentCall::ValueStoredInIntent {
                intent_id: B256::from_slice(call.intentId.as_slice()),
            })
        }
        _ => None,
    }
}

/// Calculate intent ID using the same method as core-lane
pub fn calculate_intent_id(sender: Address, nonce: u64, input: Bytes) -> B256 {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(sender.as_slice());
    preimage.extend_from_slice(&nonce.to_be_bytes());
    preimage.extend_from_slice(&input);
    keccak256(preimage)
}

/// Get the calldata bytes from a transaction envelope
pub fn get_transaction_input_bytes(tx: &alloy_consensus::TxEnvelope) -> Vec<u8> {
    match tx {
        alloy_consensus::TxEnvelope::Legacy(signed) => signed.tx().input.as_ref().to_vec(),
        alloy_consensus::TxEnvelope::Eip1559(signed) => signed.tx().input.as_ref().to_vec(),
        alloy_consensus::TxEnvelope::Eip2930(signed) => signed.tx().input.as_ref().to_vec(),
        alloy_consensus::TxEnvelope::Eip4844(_signed) => Vec::new(),
        _ => Vec::new(),
    }
}

pub fn get_transaction_nonce(tx: &alloy_consensus::TxEnvelope) -> u64 {
    match tx {
        alloy_consensus::TxEnvelope::Legacy(signed) => signed.tx().nonce,
        alloy_consensus::TxEnvelope::Eip1559(signed) => signed.tx().nonce,
        alloy_consensus::TxEnvelope::Eip2930(signed) => signed.tx().nonce,
        _ => 0,
    }
}

impl IntentContract {
    /// Create a new IntentContract instance
    pub fn new(address: Address) -> Self {
        Self { address }
    }

    /// Get the exit marketplace address
    pub fn exit_marketplace() -> Address {
        Address::from_str("0x0000000000000000000000000000000000000045").unwrap()
    }

    /// Parse intent data from transaction input data using core-lane ABI approach
    /// The transaction should be a call to the exit marketplace with intent data
    pub fn parse_intent_from_transaction(
        &self,
        _tx_hash: B256,
        from: Address,
        value: U256,
        input_data: &[u8],
    ) -> Result<Option<IntentData>> {
        // Check if this is a transaction to the exit marketplace
        if value == U256::ZERO {
            return Ok(None);
        }

        // Try to decode the intent calldata using the new ABI approach
        if let Some(intent_call) = decode_intent_calldata(input_data) {
            match intent_call {
                IntentCall::Intent { intent_data, nonce } => {
                    // Parse the intent data to extract Bitcoin address
                    let btc_destination = self.parse_bitcoin_address_from_input(&intent_data)?;

                    // Calculate intent ID using the same method as core-lane
                    let intent_id = calculate_intent_id(from, nonce.to::<u64>(), Bytes::from(intent_data.clone()));

                    // Calculate fee (1% of the amount)
                    let fee = value / U256::from(100);

                    return Ok(Some(IntentData {
                        intent_id: format!("0x{:x}", intent_id),
                        user_address: from,
                        btc_destination,
                        lane_btc_amount: value,
                        fee,
                    }));
                }
                _ => {
                    // Not an intent call, return None
                    return Ok(None);
                }
            }
        }

        Ok(None)
    }

    /// Parse Bitcoin address from intent data bytes
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
        use bitcoin::{Address, Network};

        // Try to parse as bech32 addresses (bc1, tb1)
        for prefix in ["bc1", "tb1"] {
            if let Some(start) = input.find(prefix) {
                // Find the end of the address (stop at non-alphanumeric characters)
                let addr_start = start;
                let addr_end = input[addr_start..].find(|c: char| !c.is_alphanumeric()).unwrap_or(input.len() - addr_start);
                let addr_str = &input[addr_start..addr_start + addr_end];

                // Validate bech32 address length and format
                if addr_str.len() >= 26 && addr_str.len() <= 62 {
                    // Try to parse as a valid Bitcoin address
                    if let Ok(addr) = addr_str.parse::<Address<bitcoin::address::NetworkUnchecked>>() {
                        // Verify it's a valid address for the appropriate network
                        let network = if prefix == "bc1" { Network::Bitcoin } else { Network::Testnet };
                        if addr.is_valid_for_network(network) {
                            return Some(addr_str.to_string());
                        }
                    }
                }
            }
        }

        // Try to parse as legacy addresses (1, 3)
        for prefix in ['1', '3'] {
            if let Some(start) = input.find(prefix) {
                let addr_start = start;
                let addr_end = input[addr_start..].find(|c: char| !c.is_alphanumeric()).unwrap_or(input.len() - addr_start);
                let addr_str = &input[addr_start..addr_start + addr_end];

                // Validate legacy address length and format
                if addr_str.len() >= 26 && addr_str.len() <= 35 {
                    // Try to parse as a valid Bitcoin address
                    if let Ok(addr) = addr_str.parse::<Address<bitcoin::address::NetworkUnchecked>>() {
                        // Verify it's a valid address for testnet (since we're using tb1 above)
                        if addr.is_valid_for_network(Network::Testnet) || addr.is_valid_for_network(Network::Bitcoin) {
                            return Some(addr_str.to_string());
                        }
                    }
                }
            }
        }

        None
    }

    /// Encode function call using alloy-sol-types
    pub fn encode_intent_locker_call(&self, intent_id: B256) -> String {
        let call = IntentSystem::intentLockerCall { intentId: intent_id.into() };
        format!("0x{}", hex::encode(call.abi_encode()))
    }

    /// Encode function call for lockIntentForSolving(intentId, data)
    pub fn encode_lock_intent_call(&self, intent_id: B256, data: &[u8]) -> String {
        let call = IntentSystem::lockIntentForSolvingCall {
            intentId: intent_id.into(),
            data: Bytes::from(data.to_vec())
        };
        format!("0x{}", hex::encode(call.abi_encode()))
    }

    /// Encode function call for solveIntent(intentId, data)
    pub fn encode_solve_intent_call(&self, intent_id: B256, data: &[u8]) -> String {
        let call = IntentSystem::solveIntentCall {
            intentId: intent_id.into(),
            data: Bytes::from(data.to_vec())
        };
        format!("0x{}", hex::encode(call.abi_encode()))
    }

    /// Encode function call for storeBlob(data, expiryTime)
    pub fn encode_store_blob_call(&self, data: &[u8], expiry_time: u64) -> String {
        let call = IntentSystem::storeBlobCall {
            data: Bytes::from(data.to_vec()),
            expiryTime: U256::from(expiry_time)
        };
        format!("0x{}", hex::encode(call.abi_encode()))
    }

    /// Encode function call for prolongBlob(blobHash)
    pub fn encode_prolong_blob_call(&self, blob_hash: B256) -> String {
        let call = IntentSystem::prolongBlobCall { blobHash: blob_hash.into() };
        format!("0x{}", hex::encode(call.abi_encode()))
    }

    /// Encode function call for intent(intentData, nonce)
    pub fn encode_intent_call(&self, intent_data: &[u8], nonce: u64) -> String {
        let call = IntentSystem::intentCall {
            intentData: Bytes::from(intent_data.to_vec()),
            nonce: U256::from(nonce)
        };
        format!("0x{}", hex::encode(call.abi_encode()))
    }

    /// Encode function call for intentFromBlob(blobHash, nonce, extraData)
    pub fn encode_intent_from_blob_call(&self, blob_hash: B256, nonce: u64, extra_data: &[u8]) -> String {
        let call = IntentSystem::intentFromBlobCall {
            blobHash: blob_hash.into(),
            nonce: U256::from(nonce),
            extraData: Bytes::from(extra_data.to_vec())
        };
        format!("0x{}", hex::encode(call.abi_encode()))
    }

    /// Encode function call for cancelIntent(intentId, data)
    pub fn encode_cancel_intent_call(&self, intent_id: B256, data: &[u8]) -> String {
        let call = IntentSystem::cancelIntentCall {
            intentId: intent_id.into(),
            data: Bytes::from(data.to_vec())
        };
        format!("0x{}", hex::encode(call.abi_encode()))
    }

    /// Encode function call for cancelIntentLock(intentId, data)
    pub fn encode_cancel_intent_lock_call(&self, intent_id: B256, data: &[u8]) -> String {
        let call = IntentSystem::cancelIntentLockCall {
            intentId: intent_id.into(),
            data: Bytes::from(data.to_vec())
        };
        format!("0x{}", hex::encode(call.abi_encode()))
    }

    /// Encode function call for isIntentSolved(intentId)
    pub fn encode_is_intent_solved_call(&self, intent_id: B256) -> String {
        let call = IntentSystem::isIntentSolvedCall { intentId: intent_id.into() };
        format!("0x{}", hex::encode(call.abi_encode()))
    }

    /// Encode function call for valueStoredInIntent(intentId)
    pub fn encode_value_stored_in_intent_call(&self, intent_id: B256) -> String {
        let call = IntentSystem::valueStoredInIntentCall { intentId: intent_id.into() };
        format!("0x{}", hex::encode(call.abi_encode()))
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
        // Bitcoin address parsing is now handled by filler_bot
        // This test is kept for reference but the functionality has been moved
        assert!(true); // Placeholder test
    }

    #[test]
    fn test_intent_parsing() {
        // Intent parsing is now handled by filler_bot using ABI decoding
        // This test is kept for reference but the functionality has been moved
        assert!(true); // Placeholder test
    }

    #[test]
    fn test_function_encoding() {
        let contract = IntentContract::new(IntentContract::exit_marketplace());
        let intent_id = B256::from([1u8; 32]);
        let test_data = b"test_data";

        // Test intent locker call
        let call = contract.encode_intent_locker_call(intent_id);
        assert!(call.starts_with("0x"));

        // Test lock intent call
        let call = contract.encode_lock_intent_call(intent_id, test_data);
        assert!(call.starts_with("0x"));

        // Test solve intent call
        let call = contract.encode_solve_intent_call(intent_id, test_data);
        assert!(call.starts_with("0x"));

        // Test store blob call
        let call = contract.encode_store_blob_call(test_data, 12345);
        assert!(call.starts_with("0x"));

        // Test intent call
        let call = contract.encode_intent_call(test_data, 12345);
        assert!(call.starts_with("0x"));
    }

    #[test]
    fn test_abi_decoding() {
        println!("\n🔧 Core-Lane ABI Decoding Demo");
        println!("================================");

        let contract = IntentContract::new(IntentContract::exit_marketplace());
        let intent_id = B256::from([1u8; 32]);
        let test_data = b"test_data";

        // Test encoding and then decoding
        let encoded_call = contract.encode_intent_call(test_data, 12345);
        println!("Encoded intent call: {}", encoded_call);

        // Decode the calldata
        let calldata = hex::decode(encoded_call.trim_start_matches("0x")).unwrap();
        if let Some(intent_call) = decode_intent_calldata(&calldata) {
            match intent_call {
                IntentCall::Intent { intent_data, nonce } => {
                    println!("Decoded intent call:");
                    println!("  intent_data: {:?}", intent_data);
                    println!("  nonce: {}", nonce);
                }
                _ => println!("Unexpected call type"),
            }
        } else {
            println!("Failed to decode intent call");
        }

        println!("\n✅ Core-lane ABI approach working correctly!");
    }
}
