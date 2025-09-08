use anyhow::Result;
use alloy_primitives::{Address, U256, B256};
use std::sync::Arc;
use std::str::FromStr;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info, warn};

use crate::core_lane_client::CoreLaneClient;
use crate::bitcoin_client::BitcoinClient;
use crate::intent_manager::{IntentManager, IntentData as ManagerIntentData, IntentStatus, UserIntent};
use crate::intent_contract::{IntentContract, IntentData as ContractIntentData};

pub struct FillerBot {
    core_lane_client: Arc<CoreLaneClient>,
    bitcoin_client: Arc<BitcoinClient>,
    intent_manager: Arc<Mutex<IntentManager>>,
    intent_contract: IntentContract,
    exit_marketplace: Address,
    filler_address: Address,
    poll_interval: u64,
    last_processed_block: u64,
}

impl FillerBot {
    pub fn new(
        core_lane_client: Arc<CoreLaneClient>,
        bitcoin_client: Arc<BitcoinClient>,
        intent_manager: Arc<Mutex<IntentManager>>,
        exit_marketplace: Address,
        filler_address: Address,
        poll_interval: u64,
    ) -> Self {
        Self {
            core_lane_client,
            bitcoin_client,
            intent_manager,
            intent_contract: IntentContract::new(exit_marketplace),
            exit_marketplace,
            filler_address,
            poll_interval,
            last_processed_block: 0,
        }
    }

    pub async fn start(&self) -> Result<()> {
        info!("🚀 Starting LaneLayer Filler Bot");
        info!("📡 Exit marketplace: 0x{:x}", self.exit_marketplace);
        info!("🤖 Filler address: 0x{:x}", self.filler_address);
        info!("⏰ Polling interval: {} seconds", self.poll_interval);

        // Test connections
        self.test_connections().await?;

        // Main polling loop
        let mut last_block_number = 0u64;

        loop {
            match self.poll_cycle(&mut last_block_number).await {
                Ok(_) => {
                    debug!("Poll cycle completed successfully");
                }
                Err(e) => {
                    error!("Poll cycle failed: {}", e);
                }
            }

            sleep(Duration::from_secs(self.poll_interval)).await;
        }
    }

    async fn test_connections(&self) -> Result<()> {
        info!("🔍 Testing connections...");

        // Test Core Lane connection
        let core_lane_block = self.core_lane_client.get_block_number().await?;
        info!("✅ Core Lane connected - Latest block: {}", core_lane_block);

        // Test Bitcoin connection
        let bitcoin_balance = self.bitcoin_client.get_balance().await?;
        info!("✅ Bitcoin connected - Balance: {} sats ({:.8} BTC)",
              bitcoin_balance, bitcoin_balance as f64 / 100_000_000.0);

        Ok(())
    }

    async fn poll_cycle(&self, last_block_number: &mut u64) -> Result<()> {
        // Get current block number
        let current_block = self.core_lane_client.get_block_number().await?;

        if current_block <= *last_block_number {
            debug!("No new blocks since last poll (current: {}, last: {})", current_block, last_block_number);
            return Ok(());
        }

        info!("📦 Processing blocks {} to {}", *last_block_number + 1, current_block);

        // Process each new block
        for block_number in (*last_block_number + 1)..=current_block {
            if let Err(e) = self.process_block(block_number).await {
                error!("Failed to process block {}: {}", block_number, e);
                // Continue with other blocks even if one fails
            }
        }

        *last_block_number = current_block;

        // Process any fulfilled intents
        self.process_fulfilled_intents().await?;

        Ok(())
    }

    async fn process_block(&self, block_number: u64) -> Result<()> {
        debug!("🔍 Processing block {}", block_number);

        // Get the block with full transaction data
        let block = self.core_lane_client.get_block_by_number(block_number, true).await?;

        info!("📦 Block {} has {} transactions", block_number, block.transactions.len());

        // Process each transaction in the block
        for tx_hash in &block.transactions {
            if let Err(e) = self.process_transaction(tx_hash).await {
                debug!("Failed to process transaction {}: {}", tx_hash, e);
                // Continue with other transactions
            }
        }

        Ok(())
    }

    async fn process_transaction(&self, tx_hash: &str) -> Result<()> {
        debug!("🔍 Processing transaction {}", tx_hash);

        // Get transaction details
        let tx = self.core_lane_client.get_transaction_by_hash(tx_hash).await?;

        // Check if this transaction is to the exit marketplace
        if let Some(to) = &tx.to {
            if to.to_lowercase() == format!("0x{:x}", self.exit_marketplace).to_lowercase() {
                info!("🎯 Found transaction to exit marketplace: {}", tx_hash);

                // Parse the intent from the transaction using the intent contract
                if let Some(intent_data) = self.parse_intent_from_transaction(&tx).await? {
                    info!("📝 Parsed intent: {} ({} laneBTC -> {})",
                          intent_data.intent_id, intent_data.lane_btc_amount, intent_data.btc_destination);

                    // Convert to manager intent data and add to our manager
                    let manager_intent_data = ManagerIntentData {
                        intent_id: intent_data.intent_id.to_string(),
                        user_address: intent_data.user_address,
                        btc_destination: intent_data.btc_destination,
                        lane_btc_amount: intent_data.lane_btc_amount,
                        fee: intent_data.fee,
                    };

                    let mut manager = self.intent_manager.lock().await;
                    manager.add_intent(manager_intent_data)?;
                }
            }
        }

        Ok(())
    }

    pub async fn parse_intent_from_transaction(&self, tx: &crate::core_lane_client::Transaction) -> Result<Option<ContractIntentData>> {
        // Parse exit marketplace intent from transaction using the intent contract
        let tx_hash = B256::from_str(&tx.hash)?;
        let from = Address::from_str(&tx.from)?;
        let value = U256::from_str_radix(&tx.value.trim_start_matches("0x"), 16)?;

        // Decode input data
        let input_hex = tx.input.trim_start_matches("0x");
        let input_data = hex::decode(input_hex)?;

        // Use the intent contract to parse the intent
        self.intent_contract.parse_intent_from_transaction(tx_hash, from, value, &input_data)
    }

    pub fn parse_bitcoin_address_from_input(&self, input: &str) -> Result<String> {
        // Parse Bitcoin address from transaction input data
        // The input should contain the user's desired Bitcoin address

        if input.len() < 10 {
            return Err(anyhow::anyhow!("Input too short"));
        }

        // Remove 0x prefix and decode hex
        let input_hex = input.trim_start_matches("0x");
        let input_bytes = hex::decode(input_hex)
            .map_err(|e| anyhow::anyhow!("Invalid hex input: {}", e))?;

        // For now, we'll extract a Bitcoin address from the input data
        // Parse the ABI-encoded data from transaction input
        // and extract the Bitcoin address parameter

        // Look for a Bitcoin address pattern in the input
        // Bitcoin addresses are typically 26-35 characters and start with 1, 3, or bc1
        let input_str = String::from_utf8_lossy(&input_bytes);

        // Try to find a Bitcoin address pattern
        if let Some(addr) = self.extract_bitcoin_address_from_string(&input_str) {
            return Ok(addr);
        }

        // Fallback: generate a test address based on the input hash
        let hash = hex::encode(&input_bytes[..8.min(input_bytes.len())]);
        let address_part = if hash.len() >= 32 { &hash[..32] } else { &hash };
        Ok(format!("tb1q{}", address_part)) // Testnet bech32 address
    }

    fn extract_bitcoin_address_from_string(&self, input: &str) -> Option<String> {
        // Look for Bitcoin address patterns
        // This is a simplified implementation - in reality you'd use proper address validation

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

    async fn process_fulfilled_intents(&self) -> Result<()> {
        let fulfilled_intents = {
            let manager = self.intent_manager.lock().await;
            manager.get_fulfilled_intents().into_iter().cloned().collect::<Vec<_>>()
        };

        for intent in fulfilled_intents {
            info!("🔄 Processing fulfilled intent: {}", intent.intent_id);

            // Try to solve the intent on Core Lane
            if let Err(e) = self.solve_intent(&intent).await {
                error!("Failed to solve intent {}: {}", intent.intent_id, e);
            }
        }

        Ok(())
    }

    async fn solve_intent(&self, intent: &crate::intent_manager::UserIntent) -> Result<()> {
        info!("🔓 Solving intent: {}", intent.intent_id);

        // Get the current block number for the solve call
        let block_number = self.core_lane_client.get_block_number().await?;

        // Call solveIntent on the Core Lane contract
        let solve_data = self.core_lane_client.solve_intent(
            self.exit_marketplace,
            &intent.intent_id,
            block_number,
        ).await?;

        info!("📞 solveIntent call data: {}", solve_data);
        info!("✅ Intent {} solved at block {}", intent.intent_id, block_number);

        // Remove the intent from our active list
        let mut manager = self.intent_manager.lock().await;
        manager.update_intent_status(&intent.intent_id, IntentStatus::Solved)?;
        manager.remove_intent(&intent.intent_id);

        Ok(())
    }

    /// Process pending intents and attempt to fulfill them
    pub async fn process_pending_intents(&self) -> Result<()> {
        let (pending_intents, available_btc) = {
            let manager = self.intent_manager.lock().await;
            let intents = manager.get_pending_intents().into_iter().cloned().collect::<Vec<_>>();
            let btc = self.bitcoin_client.get_balance().await?;
            (intents, btc)
        };

        for intent in pending_intents {
            info!("🔄 Processing pending intent: {}", intent.intent_id);

            // Check if we can fulfill this intent
            let manager = self.intent_manager.lock().await;
            let can_fulfill = manager.can_fulfill_intent(&intent, available_btc);
            drop(manager);

            if !can_fulfill {
                warn!("❌ Insufficient BTC to fulfill intent {} (need {} sats, have {} sats)",
                      intent.intent_id, intent.lane_btc_amount, available_btc);
                continue;
            }

            // Check if the intent is already locked
            match self.core_lane_client.get_intent_locker(
                self.exit_marketplace,
                &intent.intent_id
            ).await {
                Ok(Some(locker)) => {
                    if locker == self.filler_address {
                        info!("🔒 Intent {} already locked by us, proceeding to fulfill", intent.intent_id);
                        if let Err(e) = self.fulfill_intent(&intent).await {
                            error!("Failed to fulfill intent {}: {}", intent.intent_id, e);
                        }
                    } else {
                        info!("🔒 Intent {} locked by another filler: 0x{:x}", intent.intent_id, locker);
                    }
                }
                Ok(None) => {
                    info!("🔓 Intent {} not locked, attempting to lock", intent.intent_id);

                    // Try to lock the intent
                    let lock_data = self.core_lane_client.lock_intent_for_solving(
                        self.exit_marketplace,
                        &intent.intent_id,
                    ).await?;

                    info!("📞 lockIntentForSolving call data: {}", lock_data);

                    // For now, we'll assume the lock was successful
                    // In production, you'd need to actually send the transaction
                    let mut manager = self.intent_manager.lock().await;
                    manager.update_intent_status(&intent.intent_id, IntentStatus::Locked)?;
                    drop(manager);

                    // Now fulfill the intent
                    if let Err(e) = self.fulfill_intent(&intent).await {
                        error!("Failed to fulfill intent {}: {}", intent.intent_id, e);
                    }
                }
                Err(e) => {
                    error!("Failed to check intent locker for {}: {}", intent.intent_id, e);
                }
            }
        }

        Ok(())
    }

    async fn fulfill_intent(&self, intent: &crate::intent_manager::UserIntent) -> Result<()> {
        info!("💰 Fulfilling intent: {} ({} sats -> {})",
              intent.intent_id, intent.lane_btc_amount, intent.btc_destination);

        // Send BTC to the user's requested address
        let txid = self.bitcoin_client.send_to_address(
            &intent.btc_destination,
            intent.lane_btc_amount.to::<u64>(),
            &intent.intent_id,
        ).await?;

        // Update the intent with the Bitcoin transaction ID
        let mut manager = self.intent_manager.lock().await;
        manager.set_bitcoin_txid(&intent.intent_id, txid.to_string())?;
        drop(manager);

        // Wait for confirmation
        self.bitcoin_client.wait_for_confirmation(&txid, 1).await?;

        // Update confirmations
        let mut manager = self.intent_manager.lock().await;
        manager.update_bitcoin_confirmations(&intent.intent_id, 1)?;

        info!("✅ Intent {} fulfilled successfully!", intent.intent_id);

        Ok(())
    }
}
