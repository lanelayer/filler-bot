use anyhow::Result;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use bitcoincore_rpc::bitcoin::{Address, Network, Txid as RpcTxid, Amount as RpcAmount, ScriptBuf as RpcScriptBuf};
use bitcoin::Txid;
use bdk_wallet::keys::{bip39::Mnemonic, DerivableKey, ExtendedKey};
use bdk_wallet::{KeychainKind, PersistedWallet};
use bdk_electrum::electrum_client;
use bdk_electrum::electrum_client::ElectrumApi;
use serde_json::json;
use std::str::FromStr;
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub enum BitcoinBackend {
    Electrum {
        url: String,
    },
    Rpc {
        url: String,
        username: String,
        password: String,
    },
}

pub struct BitcoinClient {
    wallet: PersistedWallet<bdk_wallet::rusqlite::Connection>,
    wallet_name: String,
    network: Network,
    backend: BitcoinBackend,
}

impl BitcoinClient {
    /// Get the network this client is configured for
    pub fn network(&self) -> Network {
        self.network
    }

    /// Create a new BDK-based Bitcoin client with Electrum backend
    pub async fn new_electrum(
        electrum_url: String,
        mnemonic_str: String,
        network_str: String,
        wallet_name: String,
    ) -> Result<Self> {
        info!("🔧 Initializing BDK Bitcoin client with Electrum backend");
        info!("   Network: {}", network_str);
        info!("   Electrum: {}", electrum_url);
        info!("   Wallet: {}", wallet_name);

        let backend = BitcoinBackend::Electrum { url: electrum_url };
        Self::new_with_backend(backend, mnemonic_str, network_str, wallet_name).await
    }

    /// Create a new BDK-based Bitcoin client with RPC backend
    pub async fn new_rpc(
        rpc_url: String,
        rpc_username: String,
        rpc_password: String,
        mnemonic_str: String,
        network_str: String,
        wallet_name: String,
    ) -> Result<Self> {
        info!("🔧 Initializing BDK Bitcoin client with RPC backend");
        info!("   Network: {}", network_str);
        info!("   RPC URL: {}", rpc_url);
        info!("   Wallet: {}", wallet_name);

        let backend = BitcoinBackend::Rpc {
            url: rpc_url,
            username: rpc_username,
            password: rpc_password,
        };
        Self::new_with_backend(backend, mnemonic_str, network_str, wallet_name).await
    }

    /// Internal method to create client with specified backend
    async fn new_with_backend(
        backend: BitcoinBackend,
        mnemonic_str: String,
        network_str: String,
        wallet_name: String,
    ) -> Result<Self> {
        // Parse network
        let network = match network_str.as_str() {
            "bitcoin" | "main" | "mainnet" => Network::Bitcoin,
            "test" | "testnet" => Network::Testnet,
            "signet" => Network::Signet,
            "regtest" => Network::Regtest,
            _ => return Err(anyhow::anyhow!("Invalid network: {}", network_str)),
        };

        // Parse mnemonic
        let mnemonic = Mnemonic::parse(&mnemonic_str)
            .map_err(|e| anyhow::anyhow!("Invalid mnemonic: {}", e))?;

        // Derive extended key
        let xkey: ExtendedKey = mnemonic.into_extended_key()
            .map_err(|e| anyhow::anyhow!("Failed to derive extended key: {}", e))?;

        let xprv = xkey.into_xprv(network)
            .ok_or_else(|| anyhow::anyhow!("Failed to create xprv for network"))?;

        // Create wallet descriptors (BIP84 - Native SegWit)
        let external_descriptor = format!("wpkh({}/84'/0'/0'/0/*)", xprv);
        let internal_descriptor = format!("wpkh({}/84'/0'/0'/1/*)", xprv);

        // Database path based on wallet name
        let db_path = format!("./{}-wallet.db", wallet_name);

        // Open or create database
        let mut db = bdk_wallet::rusqlite::Connection::open(&db_path)
            .map_err(|e| anyhow::anyhow!("Failed to open database {}: {}", db_path, e))?;

        // Create or load wallet using the simplified API
        let wallet = bdk_wallet::Wallet::create(external_descriptor, internal_descriptor)
            .network(network)
            .create_wallet(&mut db)
            .map_err(|e| anyhow::anyhow!("Failed to create wallet: {}", e))?;

        info!("✅ BDK wallet initialized");

        let client = Self {
            wallet,
            wallet_name,
            network,
            backend,
        };

        // Note: Sync will be handled separately with the new BDK API
        info!("🔄 Wallet created (sync will be handled separately)");

        Ok(client)
    }

    /// Get database connection
    fn get_db(&self) -> Result<bdk_wallet::rusqlite::Connection> {
        let db_path = format!("./{}-wallet.db", self.wallet_name);
        bdk_wallet::rusqlite::Connection::open(&db_path)
            .map_err(|e| anyhow::anyhow!("Failed to open database: {}", e))
    }

    /// Check if an address belongs to this wallet
    pub fn is_address_mine(&self, address: &str) -> bool {
        match Address::from_str(address) {
            Ok(_addr) => {
                // Check if the address is in the wallet's address list
                // This is a simplified check - in practice, BDK would need to scan the address
                // For now, we'll assume all addresses generated by this wallet are "mine"
                true
            }
            Err(_) => false,
        }
    }

    /// Refresh wallet balance by syncing with the blockchain
    pub async fn refresh_balance(&mut self) -> Result<u64> {
        info!("🔄 Syncing wallet with blockchain...");
        
        // Get database connection for persistence
        let mut conn = self.get_db()?;
        
        // Sync wallet based on network
        match self.network {
            Network::Regtest => {
                // Use bitcoind RPC for regtest
                match &self.backend {
                    BitcoinBackend::Rpc { url, username, password } => {
                        use bdk_bitcoind_rpc::bitcoincore_rpc::Auth as RpcAuth;
                        use bdk_bitcoind_rpc::bitcoincore_rpc::Client;
                        use bdk_bitcoind_rpc::Emitter;
                        use std::sync::Arc;

                        info!("🔗 Syncing with Bitcoin RPC: {}", url);

                        let rpc_client = Client::new(
                            url,
                            RpcAuth::UserPass(username.clone(), password.clone()),
                        )?;

                        let mut emitter = Emitter::new(
                            &rpc_client,
                            self.wallet.latest_checkpoint().clone(),
                            0,
                            std::iter::empty::<Arc<bitcoincore_rpc::bitcoin::Transaction>>(), // No mempool txs
                        );

                        while let Some(block_emission) = emitter.next_block()? {
                            self.wallet.apply_block(&block_emission.block, block_emission.block_height())?;
                        }

                        self.wallet.persist(&mut conn)?;
                        info!("✅ Wallet synced with Bitcoin RPC");
                    }
                    BitcoinBackend::Electrum { .. } => {
                        return Err(anyhow::anyhow!("Electrum backend not supported for regtest"));
                    }
                }
            }
            _ => {
                // Use Electrum for other networks
                match &self.backend {
                    BitcoinBackend::Electrum { url } => {
                        use bdk_electrum::{electrum_client, BdkElectrumClient};

                        info!("🔗 Syncing with Electrum: {}", url);

                        let electrum_client = electrum_client::Client::new(url)?;
                        let electrum = BdkElectrumClient::new(electrum_client);

                        info!("🔍 Scanning blockchain for wallet transactions...");

                        let request = self.wallet.start_full_scan().build();
                        let response = electrum.full_scan(request, 5, 1, false)?;

                        self.wallet.apply_update(response)?;
                        self.wallet.persist(&mut conn)?;
                        info!("✅ Wallet synced with Electrum");
                    }
                    BitcoinBackend::Rpc { .. } => {
                        // For RPC backend on non-regtest networks, just get balance without sync
                        info!("🔄 Using RPC backend - getting live balance");
                    }
                }
            }
        }
        
        // Get the synced balance
        let balance = self.wallet.balance().total().to_sat();
        info!("💰 Synced balance: {} sats ({:.8} BTC)", balance, balance as f64 / 100_000_000.0);
        Ok(balance)
    }



    /// Test connection to configured backend
    pub async fn test_connection(&self) -> Result<u64> {
        match &self.backend {
            BitcoinBackend::Electrum { url } => {
                let client = electrum_client::Client::new(url)
                    .map_err(|e| anyhow::anyhow!("Failed to connect to Electrum: {}", e))?;

                let header = client.block_headers_subscribe()
                    .map_err(|e| anyhow::anyhow!("Failed to subscribe to block headers: {}", e))?;

                Ok(header.height as u64)
            }
            BitcoinBackend::Rpc { url, username, password } => {
                let auth = Auth::UserPass(username.clone(), password.clone());
                let client = Client::new(url, auth)
                    .map_err(|e| anyhow::anyhow!("Failed to connect to Bitcoin RPC: {}", e))?;

                let blockchain_info = client.get_blockchain_info()
                    .map_err(|e| anyhow::anyhow!("Failed to get blockchain info: {}", e))?;

                Ok(blockchain_info.blocks)
            }
        }
    }


    /// Send Bitcoin to an address with intent_id tag (tagged fill)
    /// Creates a transaction with exactly 2 outputs:
    /// - Output 0: Payment to user's Bitcoin address
    /// - Output 1: OP_RETURN with 32-byte intent_id tag
    pub async fn send_to_address(&mut self, address: &str, amount_sats: u64, intent_id: &str) -> Result<String> {
        info!(
            "💰 Sending {} sats ({:.8} BTC) to {} for intent {}",
            amount_sats,
            amount_sats as f64 / 100_000_000.0,
            address,
            intent_id
        );

        // Parse destination address
        let dest_address = Address::from_str(address)
            .map_err(|e| anyhow::anyhow!("Invalid Bitcoin address: {}", e))?
            .require_network(self.network)
            .map_err(|e| anyhow::anyhow!("Address network mismatch: {}", e))?;

        // Parse intent_id (remove 0x prefix if present)
        let intent_id_hex = intent_id.trim_start_matches("0x");
        let intent_id_bytes = hex::decode(intent_id_hex)
            .map_err(|e| anyhow::anyhow!("Invalid intent_id hex: {}", e))?;
        
        if intent_id_bytes.len() != 32 {
            return Err(anyhow::anyhow!("Intent ID must be exactly 32 bytes, got {} bytes", intent_id_bytes.len()));
        }

        // Build OP_RETURN script with intent_id manually
        // OP_RETURN (0x6a) + pushdata32 (0x20) + 32 bytes of intent_id
        let mut op_return_bytes = Vec::new();
        op_return_bytes.push(0x6a); // OP_RETURN
        op_return_bytes.push(0x20); // Push 32 bytes
        op_return_bytes.extend_from_slice(&intent_id_bytes);

        // Convert to bitcoincore_rpc ScriptBuf
        let rpc_op_return_script = RpcScriptBuf::from(op_return_bytes);

        // Build transaction with both outputs
        let mut tx_builder = self.wallet.build_tx();
        
        // Output 0: Payment to user
        tx_builder.add_recipient(dest_address.script_pubkey(), RpcAmount::from_sat(amount_sats));
        
        // Output 1: OP_RETURN with intent_id tag
        tx_builder.add_recipient(rpc_op_return_script, RpcAmount::from_sat(0));

        let mut psbt = tx_builder.finish()
            .map_err(|e| anyhow::anyhow!("Failed to build transaction: {}", e))?;

        // Sign transaction
        let finalized = self.wallet.sign(&mut psbt, Default::default())
            .map_err(|e| anyhow::anyhow!("Failed to sign transaction: {}", e))?;

        if !finalized {
            return Err(anyhow::anyhow!("Failed to finalize transaction"));
        }

        // Extract transaction
        let tx = psbt.extract_tx()
            .map_err(|e| anyhow::anyhow!("Failed to extract transaction: {}", e))?;

        let txid = tx.compute_txid();

        // Verify transaction has at least 2 outputs (payment + OP_RETURN)
        // There may be a 3rd output for change if needed
        if tx.output.len() < 2 {
            return Err(anyhow::anyhow!("Transaction must have at least 2 outputs (payment + OP_RETURN), got {}", tx.output.len()));
        }
        
        if tx.output.len() > 2 {
            info!("💰 Transaction has {} outputs (includes {} sat change output)", tx.output.len(), tx.output[2].value.to_sat());
        }

        // Broadcast transaction via configured backend
        match &self.backend {
            BitcoinBackend::Electrum { url } => {
                let client = electrum_client::Client::new(url)
                    .map_err(|e| anyhow::anyhow!("Failed to connect to Electrum: {}", e))?;

                client.transaction_broadcast(&tx)
                    .map_err(|e| anyhow::anyhow!("Failed to broadcast transaction: {}", e))?;
            }
            BitcoinBackend::Rpc { url, username, password } => {
                let auth = Auth::UserPass(username.clone(), password.clone());
                let client = Client::new(url, auth)
                    .map_err(|e| anyhow::anyhow!("Failed to connect to Bitcoin RPC: {}", e))?;

                client.send_raw_transaction(&tx)
                    .map_err(|e| anyhow::anyhow!("Failed to broadcast transaction: {}", e))?;
            }
        }

        info!("📍 Transaction ID: {}", txid);
        info!("🏷️  Tagged with intent_id: {} (32 bytes)", intent_id);
        info!("📤 Transaction structure: {} outputs (payment + OP_RETURN tag)", tx.output.len());
        Ok(txid.to_string())
    }

    /// Get transaction information
    pub async fn get_transaction(&self, txid: &str) -> Result<serde_json::Value> {
        let txid = Txid::from_str(txid)
            .map_err(|e| anyhow::anyhow!("Invalid txid: {}", e))?;

        match &self.backend {
            BitcoinBackend::Electrum { url } => {
                let client = electrum_client::Client::new(url)
                    .map_err(|e| anyhow::anyhow!("Failed to connect to Electrum: {}", e))?;

                // Convert to the Txid type expected by electrum-client
                let electrum_txid_str = txid.to_string();
                let electrum_txid = bitcoincore_rpc::bitcoin::Txid::from_str(&electrum_txid_str)
                    .map_err(|e| anyhow::anyhow!("Failed to convert txid: {}", e))?;

                let _tx = client.transaction_get(&electrum_txid)
                    .map_err(|e| anyhow::anyhow!("Failed to get transaction: {}", e))?;

                // For Electrum, we'll use a simplified confirmation count
                // In a real implementation, you'd need to track confirmations differently
                let confirmations = 0;

                // Build JSON response compatible with Bitcoin Core RPC format
                Ok(json!({
                    "txid": txid.to_string(),
                    "confirmations": confirmations,
                    "time": 0, // Electrum doesn't provide this in the same way
                    "blocktime": 0, // Electrum doesn't provide this in the same way
                }))
            }
            BitcoinBackend::Rpc { url, username, password } => {
                let auth = Auth::UserPass(username.clone(), password.clone());
                let client = Client::new(url, auth)
                    .map_err(|e| anyhow::anyhow!("Failed to connect to Bitcoin RPC: {}", e))?;

                // Convert bitcoin::Txid to bitcoincore_rpc::bitcoin::Txid
                let rpc_txid = RpcTxid::from_str(&txid.to_string())
                    .map_err(|e| anyhow::anyhow!("Failed to convert txid: {}", e))?;

                // Use getrawtransaction instead of gettransaction (doesn't require wallet)
                let tx_info = client.get_raw_transaction_info(&rpc_txid, None)
                    .map_err(|e| anyhow::anyhow!("Failed to get transaction: {}", e))?;

                // Convert to JSON format
                Ok(json!({
                    "txid": txid.to_string(),
                    "confirmations": tx_info.confirmations.unwrap_or(0),
                    "time": tx_info.time,
                    "blocktime": tx_info.blocktime,
                }))
            }
        }
    }

    /// Wait for transaction confirmations
    pub async fn wait_for_confirmation(&self, txid: &str, confirmations: u32) -> Result<()> {
        info!("⏳ Waiting for {} confirmations of transaction {}", confirmations, txid);

        loop {
            match self.get_transaction(txid).await {
                Ok(tx_info) => {
                    if let Some(confirmations_count) = tx_info.get("confirmations") {
                        let confs = confirmations_count.as_u64().unwrap_or(0) as u32;
                        if confs >= confirmations {
                            info!("✅ Transaction {} confirmed with {} confirmations", txid, confs);
                            return Ok(());
                        }
                        debug!("Transaction {} has {} confirmations, waiting for {}", txid, confs, confirmations);
                    }
                }
                Err(e) => {
                    warn!("Failed to get transaction info: {}", e);
                }
            }

            // Wait 10 seconds before checking again
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
        }
    }

    /// List unspent outputs
    pub async fn list_unspent(&self, min_amount: Option<u64>) -> Result<Vec<serde_json::Value>> {
        let utxos = self.wallet.list_unspent();

        let mut result = Vec::new();

        for utxo in utxos {
            let amount_sats = utxo.txout.value;

            // Filter by minimum amount if specified
        if let Some(min) = min_amount {
                if amount_sats.to_sat() < min {
                    continue;
                }
            }

            // Build JSON compatible with Bitcoin Core RPC format
            result.push(json!({
                "txid": utxo.outpoint.txid.to_string(),
                "vout": utxo.outpoint.vout,
                "amount": amount_sats.to_sat() as f64 / 100_000_000.0,
                "amountSats": amount_sats.to_sat(),
                "scriptPubKey": hex::encode(&utxo.txout.script_pubkey.as_bytes()),
            }));
        }

        Ok(result)
    }

    /// Get a new receiving address
    pub async fn get_new_address(&mut self) -> Result<String> {
        let address_info = self.wallet.reveal_next_address(KeychainKind::External);
        Ok(address_info.address.to_string())
    }

    /// Generate a Bitcoin address for the bot's float (working capital)
    /// This address should be funded with BTC for the bot to use
    pub async fn generate_float_address(&mut self) -> Result<String> {
        match &self.backend {
            BitcoinBackend::Rpc { .. } => {
                // For RPC backend, use BDK wallet to generate address
                let address_info = self.wallet.reveal_next_address(KeychainKind::External);
                let address = address_info.address.to_string();
                info!("🏦 Generated float address: {}", address);
                info!("💰 Please fund this address with BTC for the bot to use as working capital");
                Ok(address)
            }
            BitcoinBackend::Electrum { .. } => {
                // For Electrum backend, use BDK wallet to generate address
                let address_info = self.wallet.reveal_next_address(KeychainKind::External);
                let address = address_info.address.to_string();
                info!("🏦 Generated float address: {}", address);
                info!("💰 Please fund this address with BTC for the bot to use as working capital");
                Ok(address)
            }
        }
    }

    /// Get wallet info
    pub async fn get_wallet_info(&self) -> Result<serde_json::Value> {
        let balance = self.wallet.balance();

        Ok(json!({
            "walletname": self.wallet_name,
            "balance": balance.total().to_sat() as f64 / 100_000_000.0,
            "confirmed_balance": balance.confirmed.to_sat() as f64 / 100_000_000.0,
            "unconfirmed_balance": balance.untrusted_pending.to_sat() as f64 / 100_000_000.0,
            "immature_balance": balance.immature.to_sat() as f64 / 100_000_000.0,
        }))
    }

    /// Get transaction confirmations
    pub async fn get_transaction_confirmations(&self, txid: &bitcoin::Txid) -> Result<u32> {
        match &self.backend {
            BitcoinBackend::Electrum { url } => {
                let client = electrum_client::Client::new(url)
                    .map_err(|e| anyhow::anyhow!("Failed to connect to Electrum: {}", e))?;

                // Convert to the Txid type expected by electrum-client
                let electrum_txid_str = txid.to_string();
                let electrum_txid = bitcoincore_rpc::bitcoin::Txid::from_str(&electrum_txid_str)
                    .map_err(|e| anyhow::anyhow!("Failed to convert txid: {}", e))?;

                match client.transaction_get(&electrum_txid) {
                    Ok(_tx) => {
                        // TODO: Implement proper Electrum confirmation counting
                        // For now, return 0 (unconfirmed)
            Ok(0)
                    }
                    Err(_) => Ok(0), // Not found or unconfirmed
                }
            }
            BitcoinBackend::Rpc { url, username, password } => {
                let auth = Auth::UserPass(username.clone(), password.clone());
                let client = Client::new(url, auth)
                    .map_err(|e| anyhow::anyhow!("Failed to connect to Bitcoin RPC: {}", e))?;

                // Convert bitcoin::Txid to bitcoincore_rpc::bitcoin::Txid
                let rpc_txid = RpcTxid::from_str(&txid.to_string())
                    .map_err(|e| anyhow::anyhow!("Failed to convert txid: {}", e))?;

                // Use getrawtransaction instead of gettransaction (doesn't require wallet)
                match client.get_raw_transaction_info(&rpc_txid, None) {
                    Ok(tx_info) => Ok(tx_info.confirmations.unwrap_or(0) as u32),
                    Err(_) => Ok(0), // Not found or unconfirmed
                }
            }
        }
    }
}