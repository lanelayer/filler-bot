use crate::intent_contract::calculate_intent_id;
use alloy_consensus;
use alloy_network::{Ethereum, TxSigner};
use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rlp;
use alloy_rpc_types::TransactionRequest;
use alloy_signer_local::PrivateKeySigner;
use anyhow::{anyhow, Result};
use ciborium::from_reader;
use hex;
use std::io::Cursor;
use std::str::FromStr;

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
    async fn intent_from_blob(
        &self,
        blob_hash: B256,
        nonce: u64,
        extra_data: &[u8],
    ) -> Result<B256>;

    /// Create an intent and lock it using EIP-712 signature
    /// signer_address: The address that signed the EIP-712 message (used to calculate intent ID)
    async fn create_intent_and_lock(
        &self,
        eip712sig: &[u8],
        lock_data: &[u8],
        signer_address: Address,
    ) -> Result<B256>;

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
    provider_url: String,
    contract_address: Address,
    intent_contract: crate::intent_contract::IntentContract,
    signer: Option<PrivateKeySigner>,
}

#[derive(serde::Deserialize)]
pub struct LockData {
    pub intent: Vec<u8>,
    pub nonce: U256,
    pub value: U256,
}

impl CoreLaneIntentSystem {
    pub fn new(
        provider_url: String,
        contract_address: Address,
        signer: Option<PrivateKeySigner>,
    ) -> Self {
        Self {
            provider_url,
            contract_address,
            intent_contract: crate::intent_contract::IntentContract::new(contract_address),
            signer,
        }
    }

    fn get_provider(&self) -> impl Provider<Ethereum> + '_ {
        let url: url::Url = self.provider_url.parse().expect("Invalid URL");
        ProviderBuilder::new().connect_http(url)
    }

    /// Get the contract address
    pub fn contract_address(&self) -> Address {
        self.contract_address
    }

    /// Send a transaction to the network (requires signer)
    async fn send_transaction(
        &self,
        signer: &PrivateKeySigner,
        data: Vec<u8>,
        value: U256,
    ) -> Result<String> {
        let provider = self.get_provider();
        let from = signer.address();

        // Get the chain ID
        let chain_id = provider
            .get_chain_id()
            .await
            .map_err(|e| anyhow!("Failed to get chain ID: {}", e))?;

        // Get the nonce
        let nonce = provider
            .get_transaction_count(from)
            .await
            .map_err(|e| anyhow!("Failed to get transaction count: {}", e))?;

        // Get max fee per gas and max priority fee per gas (EIP-1559)
        let gas_price = provider
            .get_gas_price()
            .await
            .map_err(|e| anyhow!("Failed to get gas price: {}", e))?;

        // For EIP-1559, use gas price as both max_fee_per_gas and max_priority_fee_per_gas
        let max_fee_per_gas = U256::from(gas_price);
        let max_priority_fee_per_gas = U256::from(gas_price) / U256::from(10); // 10% of gas price as priority

        // Estimate gas
        let tx_request = TransactionRequest {
            from: Some(from),
            to: Some(self.contract_address.into()),
            input: Bytes::from(data.clone()).into(),
            value: Some(value),
            ..Default::default()
        };

        let gas = provider
            .estimate_gas(tx_request)
            .await
            .map_err(|e| anyhow!("Failed to estimate gas: {}", e))?;

        // Add 20% buffer to gas estimate
        let gas_u256 = U256::from(gas);
        let gas_limit = gas_u256 + (gas_u256 / U256::from(5));

        // Build the EIP-1559 transaction
        let mut tx = alloy_consensus::TxEip1559 {
            chain_id,
            nonce,
            max_fee_per_gas: max_fee_per_gas.to::<u128>(),
            max_priority_fee_per_gas: max_priority_fee_per_gas.to::<u128>(),
            gas_limit: gas_limit.to::<u64>(),
            to: alloy_primitives::TxKind::Call(self.contract_address),
            value,
            input: Bytes::from(data),
            access_list: Default::default(),
        };

        // Sign the transaction
        let signature = signer
            .sign_transaction(&mut tx)
            .await
            .map_err(|e| anyhow!("Failed to sign transaction: {}", e))?;

        // Create signed transaction and encode
        let signed_tx = alloy_consensus::TxEnvelope::Eip1559(
            alloy_consensus::Signed::new_unchecked(tx, signature, Default::default()),
        );

        let encoded = alloy_rlp::encode(&signed_tx);
        let tx_hex = format!("0x{}", hex::encode(&encoded));

        // Send the raw transaction
        let pending_tx = provider
            .send_raw_transaction(&Bytes::from_str(&tx_hex)?)
            .await
            .map_err(|e| anyhow!("Failed to send transaction: {}", e))?;

        Ok(format!("0x{:x}", pending_tx.tx_hash()))
    }
}

#[async_trait::async_trait]
impl IntentSystem for CoreLaneIntentSystem {
    async fn store_blob(&self, data: &[u8], expiry_time: u64) -> Result<String> {
        let call_data = self
            .intent_contract
            .encode_store_blob_call(data, expiry_time);
        let call_data_bytes = hex::decode(call_data.trim_start_matches("0x"))?;
        let signer = self.signer.as_ref().ok_or_else(|| {
            anyhow!("No signer configured. Use new_with_signer() to enable transaction sending.")
        })?;
        let tx_hash = self
            .send_transaction(signer, call_data_bytes, U256::ZERO)
            .await?;
        Ok(tx_hash)
    }

    async fn prolong_blob(&self, blob_hash: B256) -> Result<String> {
        let call_data = self.intent_contract.encode_prolong_blob_call(blob_hash);
        let call_data_bytes = hex::decode(call_data.trim_start_matches("0x"))?;
        let signer = self.signer.as_ref().ok_or_else(|| {
            anyhow!("No signer configured. Use new_with_signer() to enable transaction sending.")
        })?;
        let tx_hash = self
            .send_transaction(signer, call_data_bytes, U256::ZERO)
            .await?;
        Ok(tx_hash)
    }

    async fn blob_stored(&self, blob_hash: B256) -> Result<bool> {
        let call_data = self.intent_contract.encode_blob_stored_call(blob_hash);
        let provider = self.get_provider();
        let call_data_bytes = hex::decode(call_data.trim_start_matches("0x"))?;
        let tx_request = TransactionRequest {
            to: Some(self.contract_address.into()),
            input: alloy_primitives::Bytes::from(call_data_bytes).into(),
            ..Default::default()
        };
        let result = provider
            .call(tx_request)
            .await
            .map_err(|e| anyhow!("Failed to call contract: {}", e))?;
        self.intent_contract
            .parse_blob_stored_response(&format!("0x{}", hex::encode(result.as_ref())))
    }

    async fn intent(&self, intent_data: &[u8], nonce: u64) -> Result<B256> {
        let call_data = self.intent_contract.encode_intent_call(intent_data, nonce);
        let call_data_bytes = hex::decode(call_data.trim_start_matches("0x"))?;
        let signer = self.signer.as_ref().ok_or_else(|| {
            anyhow!("No signer configured. Use new_with_signer() to enable transaction sending.")
        })?;

        // Calculate the intent ID using the same method as core-lane
        let sender = signer.address();
        let intent_id = crate::intent_contract::calculate_intent_id(
            sender,
            nonce,
            Bytes::from(intent_data.to_vec()),
        );

        // Send the transaction
        let tx_hash = self
            .send_transaction(signer, call_data_bytes, U256::ZERO)
            .await?;

        // Return the calculated intent ID
        Ok(intent_id)
    }

    async fn intent_from_blob(
        &self,
        blob_hash: B256,
        nonce: u64,
        extra_data: &[u8],
    ) -> Result<B256> {
        let call_data = self
            .intent_contract
            .encode_intent_from_blob_call(blob_hash, nonce, extra_data);
        let call_data_bytes = hex::decode(call_data.trim_start_matches("0x"))?;
        let signer = self.signer.as_ref().ok_or_else(|| {
            anyhow!("No signer configured. Use new_with_signer() to enable transaction sending.")
        })?;

        // Calculate the intent ID using the same method as core-lane
        // For intentFromBlob, the input is the concatenation of blob_hash and extra_data
        let sender = signer.address();
        let mut blob_intent_input = Vec::new();
        blob_intent_input.extend_from_slice(blob_hash.as_slice());
        blob_intent_input.extend_from_slice(extra_data);

        let intent_id = crate::intent_contract::calculate_intent_id(
            sender,
            nonce,
            Bytes::from(blob_intent_input),
        );

        // Send the transaction
        let tx_hash = self
            .send_transaction(signer, call_data_bytes, U256::ZERO)
            .await?;

        // Return the calculated intent ID
        Ok(intent_id)
    }

    async fn cancel_intent(&self, intent_id: B256, data: &[u8]) -> Result<String> {
        let call_data = self
            .intent_contract
            .encode_cancel_intent_call(intent_id, data);
        let call_data_bytes = hex::decode(call_data.trim_start_matches("0x"))?;
        let signer = self.signer.as_ref().ok_or_else(|| {
            anyhow!("No signer configured. Use new_with_signer() to enable transaction sending.")
        })?;
        let tx_hash = self
            .send_transaction(signer, call_data_bytes, U256::ZERO)
            .await?;
        Ok(tx_hash)
    }

    async fn lock_intent_for_solving(&self, intent_id: B256, data: &[u8]) -> Result<String> {
        let signer = self.signer.as_ref().ok_or_else(|| {
            anyhow!("No signer configured. Use new_with_signer() to enable transaction sending.")
        })?;

        let call_data = self
            .intent_contract
            .encode_lock_intent_call(intent_id, data);
        let call_data_bytes = hex::decode(call_data.trim_start_matches("0x"))?;

        // Send the transaction
        let tx_hash = self
            .send_transaction(signer, call_data_bytes, U256::ZERO)
            .await?;
        Ok(tx_hash)
    }

    async fn solve_intent(&self, intent_id: B256, data: &[u8]) -> Result<String> {
        let signer = self.signer.as_ref().ok_or_else(|| {
            anyhow!("No signer configured. Use new_with_signer() to enable transaction sending.")
        })?;

        let call_data = self
            .intent_contract
            .encode_solve_intent_call(intent_id, data);
        let call_data_bytes = hex::decode(call_data.trim_start_matches("0x"))?;

        // Send the transaction
        let tx_hash = self
            .send_transaction(signer, call_data_bytes, U256::ZERO)
            .await?;
        Ok(tx_hash)
    }

    async fn cancel_intent_lock(&self, intent_id: B256, data: &[u8]) -> Result<String> {
        let call_data = self
            .intent_contract
            .encode_cancel_intent_lock_call(intent_id, data);
        let call_data_bytes = hex::decode(call_data.trim_start_matches("0x"))?;
        let signer = self.signer.as_ref().ok_or_else(|| {
            anyhow!("No signer configured. Use new_with_signer() to enable transaction sending.")
        })?;
        let tx_hash = self
            .send_transaction(signer, call_data_bytes, U256::ZERO)
            .await?;
        Ok(tx_hash)
    }

    async fn is_intent_solved(&self, intent_id: B256) -> Result<bool> {
        let call_data = self.intent_contract.encode_is_intent_solved_call(intent_id);
        let provider = self.get_provider();
        let call_data_bytes = hex::decode(call_data.trim_start_matches("0x"))?;
        let tx_request = TransactionRequest {
            to: Some(self.contract_address.into()),
            input: alloy_primitives::Bytes::from(call_data_bytes).into(),
            ..Default::default()
        };
        let result = provider
            .call(tx_request)
            .await
            .map_err(|e| anyhow!("Failed to call contract: {}", e))?;
        self.intent_contract
            .parse_is_intent_solved_response(&format!("0x{}", hex::encode(result.as_ref())))
    }

    async fn intent_locker(&self, intent_id: B256) -> Result<Option<Address>> {
        let call_data = self.intent_contract.encode_intent_locker_call(intent_id);
        let provider = self.get_provider();
        let call_data_bytes = hex::decode(call_data.trim_start_matches("0x"))?;
        let tx_request = TransactionRequest {
            to: Some(self.contract_address.into()),
            input: alloy_primitives::Bytes::from(call_data_bytes).into(),
            ..Default::default()
        };
        let result = provider
            .call(tx_request)
            .await
            .map_err(|e| anyhow!("Failed to call contract: {}", e))?;
        self.intent_contract
            .parse_intent_locker_response(&format!("0x{}", hex::encode(result.as_ref())))
    }

    async fn value_stored_in_intent(&self, intent_id: B256) -> Result<U256> {
        let call_data = self
            .intent_contract
            .encode_value_stored_in_intent_call(intent_id);
        let provider = self.get_provider();
        let call_data_bytes = hex::decode(call_data.trim_start_matches("0x"))?;
        let tx_request = TransactionRequest {
            to: Some(self.contract_address.into()),
            input: alloy_primitives::Bytes::from(call_data_bytes).into(),
            ..Default::default()
        };
        let result = provider
            .call(tx_request)
            .await
            .map_err(|e| anyhow!("Failed to call contract: {}", e))?;
        self.intent_contract
            .parse_value_stored_in_intent_response(&format!("0x{}", hex::encode(result.as_ref())))
    }

    async fn create_intent_and_lock(
        &self,
        eip712sig: &[u8],
        lock_data: &[u8],
        signer_address: Address,
    ) -> Result<B256> {
        let lock: LockData = from_reader(Cursor::new(lock_data))
            .map_err(|e| anyhow!("Failed to parse lock data: {}", e))?;

        let nonce = lock.nonce.to::<u64>();

        let intent_id =
            calculate_intent_id(signer_address, nonce, Bytes::from(lock.intent.clone()));

        let call_data = self
            .intent_contract
            .encode_create_intent_and_lock_call(eip712sig, lock_data);

        let call_data_bytes = hex::decode(call_data.trim_start_matches("0x"))?;
        let signer = self.signer.as_ref().ok_or_else(|| {
            anyhow!("No signer configured. Use new_with_signer() to enable transaction sending.")
        })?;

        self.send_transaction(signer, call_data_bytes, U256::ZERO)
            .await?;

        Ok(intent_id)
    }
}
