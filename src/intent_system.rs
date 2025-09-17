use anyhow::Result;
use alloy_primitives::{Address, U256, B256};

/// IntentSystem interface for Core Lane
/// This interface provides comprehensive intent management including blob storage,
/// intent creation, locking, solving, and querying capabilities.
#[async_trait::async_trait]
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
    intent_contract: crate::intent_contract::IntentContract,
}

impl CoreLaneIntentSystem {
    pub fn new(client: crate::core_lane_client::CoreLaneClient, contract_address: Address) -> Self {
        Self {
            client,
            contract_address,
            intent_contract: crate::intent_contract::IntentContract::new(contract_address),
        }
    }

    /// Get the contract address
    pub fn contract_address(&self) -> Address {
        self.contract_address
    }
}

#[async_trait::async_trait]
impl IntentSystem for CoreLaneIntentSystem {
    async fn store_blob(&self, data: &[u8], expiry_time: u64) -> Result<String> {
        let call_data = self.intent_contract.encode_store_blob_call(data, expiry_time);
        let result = self.client.call_contract(self.contract_address, &call_data).await?;
        Ok(result)
    }

    async fn prolong_blob(&self, blob_hash: B256) -> Result<String> {
        let call_data = self.intent_contract.encode_prolong_blob_call(blob_hash);
        let result = self.client.call_contract(self.contract_address, &call_data).await?;
        Ok(result)
    }

    async fn blob_stored(&self, blob_hash: B256) -> Result<bool> {
        let call_data = self.intent_contract.encode_blob_stored_call(blob_hash);
        let result = self.client.call_contract(self.contract_address, &call_data).await?;
        self.intent_contract.parse_blob_stored_response(&result)
    }

    async fn intent(&self, intent_data: &[u8], nonce: u64) -> Result<B256> {
        let call_data = self.intent_contract.encode_intent_call(intent_data, nonce);
        let result = self.client.call_contract(self.contract_address, &call_data).await?;
        self.intent_contract.parse_intent_response(&result)
    }

    async fn intent_from_blob(&self, blob_hash: B256, nonce: u64, extra_data: &[u8]) -> Result<B256> {
        let call_data = self.intent_contract.encode_intent_from_blob_call(blob_hash, nonce, extra_data);
        let result = self.client.call_contract(self.contract_address, &call_data).await?;
        self.intent_contract.parse_intent_response(&result)
    }

    async fn cancel_intent(&self, intent_id: B256, data: &[u8]) -> Result<String> {
        let call_data = self.intent_contract.encode_cancel_intent_call(intent_id, data);
        let result = self.client.call_contract(self.contract_address, &call_data).await?;
        Ok(result)
    }

    async fn lock_intent_for_solving(&self, intent_id: B256, data: &[u8]) -> Result<String> {
        let call_data = self.intent_contract.encode_lock_intent_call(intent_id, data);
        let result = self.client.call_contract(self.contract_address, &call_data).await?;
        Ok(result)
    }

    async fn solve_intent(&self, intent_id: B256, data: &[u8]) -> Result<String> {
        let call_data = self.intent_contract.encode_solve_intent_call(intent_id, data);
        let result = self.client.call_contract(self.contract_address, &call_data).await?;
        Ok(result)
    }

    async fn cancel_intent_lock(&self, intent_id: B256, data: &[u8]) -> Result<String> {
        let call_data = self.intent_contract.encode_cancel_intent_lock_call(intent_id, data);
        let result = self.client.call_contract(self.contract_address, &call_data).await?;
        Ok(result)
    }

    async fn is_intent_solved(&self, intent_id: B256) -> Result<bool> {
        let call_data = self.intent_contract.encode_is_intent_solved_call(intent_id);
        let result = self.client.call_contract(self.contract_address, &call_data).await?;
        self.intent_contract.parse_is_intent_solved_response(&result)
    }

    async fn intent_locker(&self, intent_id: B256) -> Result<Option<Address>> {
        let call_data = self.intent_contract.encode_intent_locker_call(intent_id);
        let result = self.client.call_contract(self.contract_address, &call_data).await?;
        self.intent_contract.parse_intent_locker_response(&result)
    }

    async fn value_stored_in_intent(&self, intent_id: B256) -> Result<U256> {
        let call_data = self.intent_contract.encode_value_stored_in_intent_call(intent_id);
        let result = self.client.call_contract(self.contract_address, &call_data).await?;
        self.intent_contract.parse_value_stored_in_intent_response(&result)
    }
}
