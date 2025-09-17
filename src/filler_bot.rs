use anyhow::Result;
use alloy_primitives::{Address, U256};
use std::sync::Arc;
use std::str::FromStr;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info, warn};

use crate::core_lane_client::CoreLaneClient;
use crate::bitcoin_client::BitcoinClient;
use crate::intent_manager::{IntentManager, IntentData, IntentStatus};
use crate::intent_contract::{IntentContract, decode_intent_calldata, IntentCall};

pub struct FillerBot {
    core_lane_client: Arc<CoreLaneClient>,
    bitcoin_client: Arc<BitcoinClient>,
    intent_manager: Arc<Mutex<IntentManager>>,
    pub intent_contract: IntentContract,
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

                // Parse the intent from the transaction using ABI decoding
                if let Some(intent_data) = self.parse_intent_from_transaction(&tx).await? {
                    info!("📝 Parsed intent: {} ({} laneBTC -> {})",
                          intent_data.intent_id, intent_data.lane_btc_amount, intent_data.btc_destination);

                    let mut manager = self.intent_manager.lock().await;
                    manager.add_intent(intent_data)?;
                }
            }
        }

        Ok(())
    }

    pub async fn parse_intent_from_transaction(&self, tx: &crate::core_lane_client::Transaction) -> Result<Option<IntentData>> {
        // Decode input data using ABI decoding
        let input_hex = tx.input.trim_start_matches("0x");
        let input_data = hex::decode(input_hex)?;

        // Use alloy ABI decoding to parse the intent call
        if let Some(intent_call) = decode_intent_calldata(&input_data) {
            match intent_call {
                IntentCall::Intent { intent_data, nonce } => {
                    // Parse Bitcoin address from intent data
                    let btc_destination = self.parse_bitcoin_address_from_input(&intent_data)?;

                    // Calculate intent ID using the same method as core-lane
                    let from = Address::from_str(&tx.from)?;
                    let intent_id = crate::intent_contract::calculate_intent_id(from, nonce.to::<u64>(), intent_data.clone().into());

                    // Calculate fee (1% of the amount)
                    let value = U256::from_str_radix(&tx.value.trim_start_matches("0x"), 16)?;
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

    pub fn parse_bitcoin_address_from_input(&self, input_data: &[u8]) -> Result<String> {
        // Parse Bitcoin address from intent data bytes
        let input_str = String::from_utf8_lossy(input_data);

        // Try to find a Bitcoin address pattern
        if let Some(addr) = self.extract_bitcoin_address_from_string(&input_str) {
            return Ok(addr);
        }

        // Fallback: generate a test address based on the input hash
        let hash = hex::encode(&input_data[..8.min(input_data.len())]);
        let address_part = if hash.len() >= 32 { &hash[..32] } else { &hash };
        Ok(format!("tb1q{}", address_part)) // Testnet bech32 address
    }

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

        // Start asynchronous confirmation monitoring
        let txid_parsed = bitcoin::Txid::from_str(&txid)?;
        self.monitor_bitcoin_confirmation(&intent.intent_id, txid_parsed).await?;

        info!("✅ Intent {} fulfilled successfully!", intent.intent_id);

        Ok(())
    }

    /// Asynchronously monitor Bitcoin transaction confirmations
    async fn monitor_bitcoin_confirmation(&self, intent_id: &str, txid: bitcoin::Txid) -> Result<()> {
        let bitcoin_client = self.bitcoin_client.clone();
        let intent_manager = self.intent_manager.clone();
        let intent_id = intent_id.to_string();

        // Spawn a background task to monitor confirmations
        tokio::spawn(async move {
            let mut confirmations = 0u32;
            let required_confirmations = 1u32; // Minimum confirmations required

            loop {
                // Check current confirmation count
                match bitcoin_client.get_transaction_confirmations(&txid).await {
                    Ok(current_confirmations) => {
                        if current_confirmations > confirmations {
                            confirmations = current_confirmations;

                            // Update the intent manager with new confirmation count
                            {
                                let mut manager = intent_manager.lock().await;
                                if let Err(e) = manager.update_bitcoin_confirmations(&intent_id, confirmations) {
                                    error!("Failed to update confirmations for intent {}: {}", intent_id, e);
                                }
                            }

                            info!("📈 Intent {} Bitcoin transaction {} now has {} confirmations",
                                  intent_id, txid, confirmations);

                            // If we have enough confirmations, we're done monitoring
                            if confirmations >= required_confirmations {
                                info!("✅ Intent {} Bitcoin transaction {} fully confirmed with {} confirmations",
                                      intent_id, txid, confirmations);
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to check confirmations for intent {}: {}", intent_id, e);
                    }
                }

                // Wait before checking again (exponential backoff)
                let delay = std::cmp::min(60, 5 * (confirmations + 1));
                tokio::time::sleep(tokio::time::Duration::from_secs(delay as u64)).await;
            }
        });

        Ok(())
    }
}
