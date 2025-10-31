use anyhow::Result;
use alloy_primitives::{Address, U256, B256};
use std::sync::Arc;
use std::str::FromStr;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info, warn};

use crate::core_lane_client::CoreLaneClient;
use crate::bitcoin_client::BitcoinClient;
use crate::intent_manager::{IntentManager, IntentData, IntentStatus};
use crate::intent_contract::{IntentContract, decode_intent_calldata, IntentCall};
use crate::intent_system::{IntentSystem, CoreLaneIntentSystem};
use crate::intent_types::{IntentData as CborIntentData, IntentType};

pub struct FillerBot {
    core_lane_client: Arc<CoreLaneClient>,
    bitcoin_client: Arc<Mutex<BitcoinClient>>,
    intent_manager: Arc<Mutex<IntentManager>>,
    pub intent_contract: IntentContract,
    intent_system: CoreLaneIntentSystem,
    exit_marketplace: Address,
    filler_address: Address,
    poll_interval: u64,
    last_processed_block: u64,
}

impl FillerBot {
    pub fn new(
        core_lane_client: Arc<CoreLaneClient>,
        bitcoin_client: Arc<Mutex<BitcoinClient>>,
        intent_manager: Arc<Mutex<IntentManager>>,
        exit_marketplace: Address,
        filler_address: Address,
        poll_interval: u64,
    ) -> Self {
        let intent_system = CoreLaneIntentSystem::new(
            (*core_lane_client).clone(),
            exit_marketplace,
        );

        Self {
            core_lane_client,
            bitcoin_client,
            intent_manager,
            intent_contract: IntentContract::new(exit_marketplace),
            intent_system,
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

        // Test Bitcoin connection and generate float address
        let mut bitcoin_client = self.bitcoin_client.lock().await;
        let bitcoin_balance = bitcoin_client.refresh_balance().await?;
        info!("✅ Bitcoin connected - Wallet Balance: {} sats ({:.8} BTC)",
              bitcoin_balance, bitcoin_balance as f64 / 100_000_000.0);

        // Generate and display float address for funding
        let float_address = bitcoin_client.generate_float_address().await?;
        
        // Use the synced wallet balance instead of individual address balance
        info!("📍 Wallet Balance (synced): {} sats ({:.8} BTC)", 
              bitcoin_balance, bitcoin_balance as f64 / 100_000_000.0);
        
        info!("");
        info!("🏦 ===== BOT FUNDING ADDRESS =====");
        info!("📍 Float Address: {}", float_address);
        info!("💰 Wallet Balance: {} sats ({:.8} BTC)", bitcoin_balance, bitcoin_balance as f64 / 100_000_000.0);
        info!("💡 Send BTC to this address to fund the bot's working capital");
        info!("🏦 ================================");
        info!("");

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

        // Process any pending intents
        self.process_pending_intents().await?;

        // Process any fulfilled intents
        self.process_fulfilled_intents().await?;

        Ok(())
    }

    /// Check bot balance and warn if it's low (with blockchain sync)
    async fn check_balance(&self) -> Result<()> {
        let mut bitcoin_client = self.bitcoin_client.lock().await;
        
        // Sync with blockchain and get fresh balance
        let balance = bitcoin_client.refresh_balance().await?;
        
        // Define low balance threshold (e.g., 100,000 sats = 0.001 BTC)
        let low_balance_threshold = 100_000; // 0.001 BTC
        
        if balance < low_balance_threshold {
            warn!("⚠️  LOW BALANCE WARNING!");
            warn!("💰 Current balance: {} sats ({:.8} BTC)", balance, balance as f64 / 100_000_000.0);
            warn!("💡 Please fund the bot's float address to continue operations");
            warn!("🏦 Minimum recommended: {} sats ({:.8} BTC)", low_balance_threshold, low_balance_threshold as f64 / 100_000_000.0);
        } else {
            debug!("💰 Balance check: {} sats ({:.8} BTC) - OK", balance, balance as f64 / 100_000_000.0);
        }
        
        Ok(())
    }

    async fn process_block(&self, block_number: u64) -> Result<()> {
        debug!("🔍 Processing block {}", block_number);

        // Get the block with full transaction data
        let block = self.core_lane_client.get_block_by_number(block_number, true).await?;

        info!("📦 Block {} has {} transactions", block_number, block.transactions.len());

        // Sync and print balance for every block
        let mut bitcoin_client = self.bitcoin_client.lock().await;
        let balance = bitcoin_client.refresh_balance().await?;
        info!("💰 Bot Balance at Block {} (synced): {} sats ({:.8} BTC)", 
              block_number, balance, balance as f64 / 100_000_000.0);
        drop(bitcoin_client);

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
            let expected = format!("0x{:x}", self.exit_marketplace).to_lowercase();
            debug!("🔍 Transaction to: {}, expected: {}", to.to_lowercase(), expected);
            if to.to_lowercase() == expected {
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
                    // Parse CBOR intent data
                    debug!("📦 Parsing CBOR intent data ({} bytes)", intent_data.len());
                    let cbor_intent = CborIntentData::from_cbor(&intent_data)?;
                    debug!("✅ CBOR parsed successfully, type: {:?}", cbor_intent.intent_type);

                    // Parse Bitcoin address and amount from CBOR intent data
                    debug!("🔍 Parsing Bitcoin address from intent...");
                    let btc_destination = self.parse_bitcoin_address_from_cbor_intent(&cbor_intent).await?;
                    debug!("✅ Bitcoin address parsed: {}", btc_destination);
                    
                    // Parse the actual amount from the CBOR data
                    let fill_data = cbor_intent.parse_anchor_bitcoin_fill()?;
                    let actual_btc_amount = fill_data.amount; // This is the amount to send in BTC
                    let max_fee = fill_data.max_fee;
                    debug!("💰 Intent amount: {} sats, max_fee: {} sats", actual_btc_amount, max_fee);

                    // Calculate intent ID using the same method as core-lane
                    // Core Lane uses the TRANSACTION nonce, not the intent function parameter nonce
                    let from = Address::from_str(&tx.from)?;
                    let tx_nonce = u64::from_str_radix(&tx.nonce.trim_start_matches("0x"), 16)?;
                    debug!("Calculating intent ID: sender={:?}, tx_nonce={}, intent_data_len={}", from, tx_nonce, intent_data.len());
                    debug!("Note: intent function nonce parameter = {}, but using tx nonce for ID", nonce);
                    let intent_id = crate::intent_contract::calculate_intent_id(from, tx_nonce, intent_data.clone().into());
                    debug!("Calculated intent_id: {:?}", intent_id);

                    // Convert locked value from wei to sats (1 sat = 1 gwei = 10^9 wei)
                    let value_wei = U256::from_str_radix(&tx.value.trim_start_matches("0x"), 16)?;
                    let gwei = U256::from(1_000_000_000u64);
                    let locked_value_sats = value_wei / gwei;
                    
                    debug!("💰 Intent locked value: {} wei = {} sats (amount={}, fee={})", 
                           value_wei, locked_value_sats, actual_btc_amount, max_fee);

                    return Ok(Some(IntentData {
                        intent_id: format!("0x{:x}", intent_id),
                        user_address: from,
                        btc_destination,
                        lane_btc_amount: actual_btc_amount, // Store the actual BTC amount to send, not the total locked
                        fee: max_fee,
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

    /// Parse Bitcoin address from CBOR intent data
    pub async fn parse_bitcoin_address_from_cbor_intent(&self, cbor_intent: &CborIntentData) -> Result<String> {
        match cbor_intent.intent_type {
            IntentType::AnchorBitcoinFill => {
                debug!("Parsing AnchorBitcoinFill from CBOR data...");
                let fill_data = cbor_intent.parse_anchor_bitcoin_fill()
                    .map_err(|e| anyhow::anyhow!("Failed to parse AnchorBitcoinFill from CBOR: {}", e))?;
                debug!("Fill data parsed: amount={}, max_fee={}, expire_by={}", fill_data.amount, fill_data.max_fee, fill_data.expire_by);
                
                let bitcoin_client = self.bitcoin_client.lock().await;
                let network = bitcoin_client.network();
                drop(bitcoin_client);
                
                debug!("Parsing Bitcoin address for network: {:?}", network);
                fill_data.parse_bitcoin_address(network)
                    .map_err(|e| anyhow::anyhow!("Failed to parse Bitcoin address: {}", e))
            }
        }
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

        // Get the Bitcoin txid from the intent
        let bitcoin_txid = intent.bitcoin_txid.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No Bitcoin txid found for intent"))?;

        // Get the Bitcoin transaction info to find which block it's in
        let bitcoin_client = self.bitcoin_client.lock().await;
        let tx_info = bitcoin_client.get_transaction(bitcoin_txid).await?;
        drop(bitcoin_client);
        
        // Extract the block number from the transaction info
        // Core Lane uses Bitcoin block numbers, not Core Lane block numbers
        let bitcoin_block_number = tx_info.get("blockheight")
            .or_else(|| tx_info.get("block_height"))
            .or_else(|| tx_info.get("blockNumber"))
            .and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow::anyhow!("No block height in transaction info: {:?}", tx_info))?;

        info!("📍 Bitcoin transaction {} is in Bitcoin block {}", bitcoin_txid, bitcoin_block_number);

        // Prepare solve data: block_height (8 bytes) + txid (32 bytes)
        let mut solve_data = Vec::new();
        solve_data.extend_from_slice(&bitcoin_block_number.to_le_bytes());
        
        // Parse Bitcoin txid and convert to 32 bytes (internal byte order)
        // Bitcoin txids are displayed in reversed byte order, but stored internally in forward order
        let txid_parsed = bitcoin::Txid::from_str(bitcoin_txid)
            .map_err(|e| anyhow::anyhow!("Failed to parse Bitcoin txid '{}': {}", bitcoin_txid, e))?;
        
        // Get the internal byte representation (not display order)
        use bitcoin::hashes::Hash;
        let txid_bytes = txid_parsed.to_byte_array();
        
        debug!("Bitcoin txid (display): {}", bitcoin_txid);
        debug!("Bitcoin txid (internal bytes): {}", hex::encode(txid_bytes));
        
        solve_data.extend_from_slice(&txid_bytes);

        debug!("Solve data: block_number={}, txid={}, total_bytes={}", bitcoin_block_number, bitcoin_txid, solve_data.len());

        // Call solveIntent on the Core Lane contract using IntentSystem
        let intent_id_bytes = B256::from_str(&intent.intent_id)?;
        let tx_hash = self.intent_system.solve_intent(intent_id_bytes, &solve_data).await?;

        info!("✅ solveIntent transaction sent: {}", tx_hash);
        
        // Wait a bit for the transaction to be mined
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
        
        // Verify the intent is actually solved on Core Lane
        match self.intent_system.is_intent_solved(intent_id_bytes).await {
            Ok(true) => {
                info!("✅ Intent {} solved successfully at Bitcoin block {} with Bitcoin tx {}", 
                      intent.intent_id, bitcoin_block_number, bitcoin_txid);
                
                // Remove the intent from our active list
                let mut manager = self.intent_manager.lock().await;
                manager.update_intent_status(&intent.intent_id, IntentStatus::Solved)?;
                manager.remove_intent(&intent.intent_id);
            }
            Ok(false) => {
                warn!("⚠️  Solve transaction sent but intent {} not marked as solved on Core Lane yet, will retry", intent.intent_id);
                // Keep the intent in Fulfilled status so we retry solving next cycle
            }
            Err(e) => {
                error!("Failed to check if intent {} is solved: {}", intent.intent_id, e);
            }
        }

        Ok(())
    }

    /// Process pending intents and attempt to fulfill them
    pub async fn process_pending_intents(&self) -> Result<()> {
        let (pending_intents, awaiting_lock_intents) = {
            let manager = self.intent_manager.lock().await;
            let pending = manager.get_pending_intents().into_iter().cloned().collect::<Vec<_>>();
            let awaiting_lock = manager.get_intents_by_status(IntentStatus::AwaitingSuccessfulLock).into_iter().cloned().collect::<Vec<_>>();
            drop(manager);
            
            (pending, awaiting_lock)
        };

        // Process intents awaiting successful lock confirmation
        for intent in awaiting_lock_intents {
            info!("⏳ Checking lock status for intent: {}", intent.intent_id);

            let intent_id_bytes = B256::from_str(&intent.intent_id)?;
            match self.intent_system.intent_locker(intent_id_bytes).await {
                Ok(Some(locker)) => {
                    if locker == self.filler_address {
                        info!("✅ Intent {} successfully locked by us, proceeding to fulfill", intent.intent_id);

                        // Update status to locked
                        let mut manager = self.intent_manager.lock().await;
                        manager.update_intent_status(&intent.intent_id, IntentStatus::Locked)?;
                        drop(manager);

                        // Now fulfill the intent
                        if let Err(e) = self.fulfill_intent(&intent).await {
                            error!("Failed to fulfill intent {}: {}", intent.intent_id, e);
                        }
                    } else {
                        info!("🔒 Intent {} locked by another filler: 0x{:x}", intent.intent_id, locker);

                        // Update status to failed since we didn't get the lock
                        let mut manager = self.intent_manager.lock().await;
                        manager.update_intent_status(&intent.intent_id, IntentStatus::Failed)?;
                        drop(manager);
                    }
                }
                Ok(None) => {
                    info!("⏳ Intent {} still not locked, continuing to wait", intent.intent_id);
                    // Keep waiting for lock confirmation
                }
                Err(e) => {
                    error!("Failed to check intent locker for {}: {}", intent.intent_id, e);
                }
            }
        }

        // Only refresh balance if there are pending intents to process
        if pending_intents.len() == 0 {
            return Ok(());
        }

        let available_btc = {
            let mut bitcoin_client = self.bitcoin_client.lock().await;
            let btc = bitcoin_client.refresh_balance().await?;
            drop(bitcoin_client);
            btc
        };

        // Process new pending intents
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

            // Check if the intent is already locked using IntentSystem
            let intent_id_bytes = B256::from_str(&intent.intent_id)?;

            match self.intent_system.intent_locker(intent_id_bytes).await {
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

                    // Try to lock the intent using IntentSystem
                    let tx_hash = self.intent_system.lock_intent_for_solving(intent_id_bytes, b"").await?;
                    info!("🔒 lockIntentForSolving transaction sent: {}", tx_hash);

                    // Update status to awaiting successful lock
                    let mut manager = self.intent_manager.lock().await;
                    manager.update_intent_status(&intent.intent_id, IntentStatus::AwaitingSuccessfulLock)?;
                    drop(manager);

                }
                Err(e) => {
                    error!("Failed to check intent locker for {}: {}", intent.intent_id, e);
                }
            }
        }

        Ok(())
    }

    async fn fulfill_intent(&self, intent: &crate::intent_manager::UserIntent) -> Result<()> {
        info!("💰 Fulfilling intent: {} ({} sats + {} fee -> {})",
              intent.intent_id, intent.lane_btc_amount, intent.fee, intent.btc_destination);

        // Send BTC to the user's requested address
        // lane_btc_amount now contains the actual BTC amount from CBOR (not including fee)
        let txid = self.bitcoin_client.lock().await.send_to_address(
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
                match bitcoin_client.lock().await.get_transaction_confirmations(&txid).await {
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
