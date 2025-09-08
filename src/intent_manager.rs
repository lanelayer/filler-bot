use anyhow::Result;
use alloy_primitives::{Address, U256};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct UserIntent {
    pub intent_id: String,
    pub user_address: Address,
    pub btc_destination: String, // Bitcoin address where user wants BTC
    pub lane_btc_amount: U256,
    pub fee: U256,
    pub status: IntentStatus,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub bitcoin_txid: Option<String>, // Our BTC transaction ID
    pub bitcoin_confirmations: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IntentStatus {
    Pending,    // Intent detected but not yet locked
    Locked,     // We've locked the intent for solving
    Fulfilling, // We're in the process of fulfilling (sent BTC)
    Fulfilled,  // BTC sent and confirmed, ready to solve
    Solved,     // Intent solved on Core Lane
    Failed,     // Something went wrong
}

#[derive(Debug, Clone)]
pub struct IntentData {
    pub intent_id: String,
    pub user_address: Address,
    pub btc_destination: String,
    pub lane_btc_amount: U256,
    pub fee: U256,
}

pub struct IntentManager {
    active_intents: HashMap<String, UserIntent>,
    // Track intents we're currently processing to avoid duplicates
    processing_intents: std::collections::HashSet<String>,
}

impl IntentManager {
    pub fn new() -> Self {
        Self {
            active_intents: HashMap::new(),
            processing_intents: std::collections::HashSet::new(),
        }
    }

    pub fn add_intent(&mut self, intent_data: IntentData) -> Result<()> {
        let intent_id = intent_data.intent_id.clone();

        // Check if we're already processing this intent
        if self.processing_intents.contains(&intent_id) {
            debug!("Intent {} is already being processed, skipping", intent_id);
            return Ok(());
        }

        // Check if we already have this intent
        if self.active_intents.contains_key(&intent_id) {
            debug!("Intent {} already exists, skipping", intent_id);
            return Ok(());
        }

        let btc_dest = intent_data.btc_destination.clone();
        let intent = UserIntent {
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

        self.active_intents.insert(intent_id.clone(), intent);
        self.processing_intents.insert(intent_id.clone());

        info!("📝 Added new intent: {} ({} laneBTC -> {})",
              intent_id, intent_data.lane_btc_amount, btc_dest);

        Ok(())
    }

    pub fn get_intent(&self, intent_id: &str) -> Option<&UserIntent> {
        self.active_intents.get(intent_id)
    }

    pub fn get_intent_mut(&mut self, intent_id: &str) -> Option<&mut UserIntent> {
        self.active_intents.get_mut(intent_id)
    }

    pub fn update_intent_status(&mut self, intent_id: &str, status: IntentStatus) -> Result<()> {
        if let Some(intent) = self.active_intents.get_mut(intent_id) {
            info!("🔄 Intent {} status: {:?} -> {:?}", intent_id, intent.status, status);
            intent.status = status;
            Ok(())
        } else {
            Err(anyhow::anyhow!("Intent {} not found", intent_id))
        }
    }

    pub fn set_bitcoin_txid(&mut self, intent_id: &str, txid: String) -> Result<()> {
        if let Some(intent) = self.active_intents.get_mut(intent_id) {
            intent.bitcoin_txid = Some(txid);
            intent.status = IntentStatus::Fulfilling;
            info!("🔗 Intent {} linked to Bitcoin transaction: {}", intent_id, intent.bitcoin_txid.as_ref().unwrap());
            Ok(())
        } else {
            Err(anyhow::anyhow!("Intent {} not found", intent_id))
        }
    }

    pub fn update_bitcoin_confirmations(&mut self, intent_id: &str, confirmations: u32) -> Result<()> {
        if let Some(intent) = self.active_intents.get_mut(intent_id) {
            intent.bitcoin_confirmations = Some(confirmations);

            // If we have enough confirmations, mark as fulfilled
            if confirmations >= 1 { // Require at least 1 confirmation
                intent.status = IntentStatus::Fulfilled;
                info!("✅ Intent {} Bitcoin transaction confirmed with {} confirmations", intent_id, confirmations);
            }

            Ok(())
        } else {
            Err(anyhow::anyhow!("Intent {} not found", intent_id))
        }
    }

    pub fn remove_intent(&mut self, intent_id: &str) -> Option<UserIntent> {
        self.processing_intents.remove(intent_id);
        self.active_intents.remove(intent_id)
    }

    pub fn get_pending_intents(&self) -> Vec<&UserIntent> {
        self.active_intents
            .values()
            .filter(|intent| intent.status == IntentStatus::Pending)
            .collect()
    }

    pub fn get_fulfilled_intents(&self) -> Vec<&UserIntent> {
        self.active_intents
            .values()
            .filter(|intent| intent.status == IntentStatus::Fulfilled)
            .collect()
    }

    pub fn get_all_intents(&self) -> Vec<&UserIntent> {
        self.active_intents.values().collect()
    }

    pub fn get_intent_count(&self) -> usize {
        self.active_intents.len()
    }

    pub fn get_intent_count_by_status(&self, status: IntentStatus) -> usize {
        self.active_intents
            .values()
            .filter(|intent| intent.status == status)
            .count()
    }

    /// Check if we have enough BTC to fulfill an intent
    pub fn can_fulfill_intent(&self, intent: &UserIntent, available_btc_sats: u64) -> bool {
        // Convert laneBTC amount to sats (assuming 1:1 ratio for now)
        let required_sats = intent.lane_btc_amount.to::<u64>();
        let fee_sats = intent.fee.to::<u64>();
        let total_required = required_sats + fee_sats;

        available_btc_sats >= total_required
    }

    /// Generate a unique intent ID for testing purposes
    pub fn generate_test_intent_id() -> String {
        format!("0x{}", hex::encode(Uuid::new_v4().as_bytes()))
    }
}

impl Default for IntentManager {
    fn default() -> Self {
        Self::new()
    }
}
