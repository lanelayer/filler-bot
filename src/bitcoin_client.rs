use anyhow::Result;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use serde_json::json;
use std::str::FromStr;
use tracing::{debug, info, warn};

pub struct BitcoinClient {
    client: Client,
    wallet_name: String,
    network: bitcoincore_rpc::bitcoin::Network,
}

impl BitcoinClient {
    pub async fn new(rpc_url: String, rpc_user: String, rpc_password: String, wallet_name: String) -> Result<Self> {
        let client = Client::new(
            &rpc_url,
            Auth::UserPass(rpc_user, rpc_password),
        )?;

        let blockchain_info: serde_json::Value = client.call("getblockchaininfo", &[])?;

        let network = if let Some(chain) = blockchain_info.get("chain") {
            match chain.as_str() {
                Some("main") => bitcoincore_rpc::bitcoin::Network::Bitcoin,
                Some("test") => bitcoincore_rpc::bitcoin::Network::Testnet,
                Some("regtest") => bitcoincore_rpc::bitcoin::Network::Regtest,
                Some(chain) => return Err(anyhow::anyhow!("Unknown chain type: {}", chain)),
                None => return Err(anyhow::anyhow!("Chain field is not a string")),
            }
        } else {
            return Err(anyhow::anyhow!("No 'chain' field found in getblockchaininfo response"));
        };

        Ok(Self {
            client,
            wallet_name,
            network,
        })
    }

    pub async fn test_connection(&self) -> Result<u64> {
        let block_count = self.client.get_block_count()?;
        Ok(block_count)
    }

    pub async fn get_balance(&self) -> Result<u64> {
        let balances: serde_json::Value = self.client.call("getbalances", &[])?;

        if let Some(wallet) = balances.get(&self.wallet_name) {
            if let Some(trusted) = wallet.get("trusted") {
                let balance_btc = trusted.as_f64().unwrap_or(0.0);
                let balance_sats = (balance_btc * 100_000_000.0) as u64;
                Ok(balance_sats)
            } else {
                Ok(0)
            }
        } else {
            Ok(0)
        }
    }

    pub async fn send_to_address(&self, address: &str, amount_sats: u64, intent_id: &str) -> Result<String> {
        // Convert sats to BTC
        let amount_btc = amount_sats as f64 / 100_000_000.0;

        // Create a comment that includes the intent ID for tracking
        let comment = format!("Filler bot fulfillment for intent: {}", intent_id);

        // Parse the address first
        let btc_address = bitcoincore_rpc::bitcoin::Address::from_str(address)?
            .require_network(self.network)?;

        // Send the transaction using the correct types
        let txid = self.client.send_to_address(
            &btc_address,
            bitcoincore_rpc::bitcoin::Amount::from_sat(amount_sats),
            Some(&comment),
            None, // comment_to
            Some(false), // subtract_fee
            Some(false), // replaceable
            Some(6), // conf_target
            Some(bitcoincore_rpc::json::EstimateMode::Conservative), // estimate_mode
        )?;

        info!(
            "💰 Sent {} sats ({:.8} BTC) to {} for intent {}",
            amount_sats, amount_btc, address, intent_id
        );
        info!("📍 Transaction ID: {}", txid);

        Ok(txid.to_string())
    }

    pub async fn get_transaction(&self, txid: &str) -> Result<serde_json::Value> {
        let tx_info: serde_json::Value = self.client.call("gettransaction", &[json!(txid)])?;
        Ok(tx_info)
    }

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

    pub async fn list_unspent(&self, min_amount: Option<u64>) -> Result<Vec<serde_json::Value>> {
        let mut params = vec![
            json!(0), // minconf
            json!(9999999), // maxconf
            json!([]), // addresses
            json!(true), // include_unsafe
        ];

        if let Some(min) = min_amount {
            let min_btc = min as f64 / 100_000_000.0;
            params.push(json!({"minimumAmount": min_btc}));
        }

        let unspent: Vec<serde_json::Value> = self.client.call("listunspent", &params)?;
        Ok(unspent)
    }

    pub async fn get_new_address(&self) -> Result<String> {
        let address: String = self.client.call("getnewaddress", &[json!(&self.wallet_name)])?;
        Ok(address)
    }

    pub async fn get_wallet_info(&self) -> Result<serde_json::Value> {
        let info: serde_json::Value = self.client.call("getwalletinfo", &[])?;
        Ok(info)
    }

    pub async fn get_transaction_confirmations(&self, txid: &bitcoin::Txid) -> Result<u32> {
        let tx_info: serde_json::Value = self.client.call("gettransaction", &[json!(txid.to_string())])?;

        if let Some(confirmations) = tx_info.get("confirmations") {
            Ok(confirmations.as_u64().unwrap_or(0) as u32)
        } else {
            Ok(0)
        }
    }

}
