use anyhow::{anyhow, Result};
use alloy_primitives::{Address, U256};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Serialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    method: String,
    params: Vec<Value>,
    id: u64,
}

#[derive(Debug, Deserialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    result: Option<Value>,
    error: Option<JsonRpcError>,
    id: u64,
}

#[derive(Debug, Deserialize)]
struct JsonRpcError {
    code: i32,
    message: String,
}

#[derive(Debug, Deserialize)]
pub struct Block {
    pub number: String,
    pub hash: String,
    pub parent_hash: String,
    pub timestamp: String,
    pub transactions: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct Transaction {
    pub hash: String,
    pub from: String,
    pub to: Option<String>,
    pub value: String,
    pub input: String,
    pub gas: String,
    pub gas_price: String,
    pub nonce: String,
    pub block_number: Option<String>,
    pub block_hash: Option<String>,
    pub transaction_index: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TransactionReceipt {
    pub transaction_hash: String,
    pub block_number: String,
    pub transaction_index: String,
    pub from: String,
    pub to: Option<String>,
    pub gas_used: String,
    pub status: String,
    pub logs: Vec<Value>,
}

#[derive(Clone)]
pub struct CoreLaneClient {
    client: Client,
    base_url: String,
}

impl CoreLaneClient {
    pub fn new(base_url: String) -> Self {
        Self {
            client: Client::new(),
            base_url,
        }
    }

    async fn call_rpc(&self, method: &str, params: Vec<Value>) -> Result<Value> {
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params,
            id: 1,
        };

        let response = self
            .client
            .post(&self.base_url)
            .json(&request)
            .send()
            .await?;

        let json_response: JsonRpcResponse = response.json().await?;

        if let Some(error) = json_response.error {
            return Err(anyhow!("RPC Error {}: {}", error.code, error.message));
        }

        json_response.result
            .ok_or_else(|| anyhow!("No result in RPC response"))
    }

    pub async fn test_connection(&self) -> Result<u64> {
        let result = self.call_rpc("eth_blockNumber", vec![]).await?;
        let block_number_hex = result.as_str()
            .ok_or_else(|| anyhow!("Invalid block number response"))?;

        let block_number = u64::from_str_radix(block_number_hex.trim_start_matches("0x"), 16)?;
        Ok(block_number)
    }

    pub async fn get_block_number(&self) -> Result<u64> {
        self.test_connection().await
    }

    /// Poll for new blocks and return the latest block number
    pub async fn poll_latest_block(&self) -> Result<u64> {
        self.get_block_number().await
    }

    pub async fn get_block_by_number(&self, block_number: u64, full_transactions: bool) -> Result<Block> {
        let block_hex = format!("0x{:x}", block_number);
        let params = vec![
            json!(block_hex),
            json!(full_transactions),
        ];

        let result = self.call_rpc("eth_getBlockByNumber", params).await?;

        if result.is_null() {
            return Err(anyhow!("Block {} not found", block_number));
        }

        let block: Block = serde_json::from_value(result)?;
        Ok(block)
    }

    pub async fn get_transaction_by_hash(&self, tx_hash: &str) -> Result<Transaction> {
        let params = vec![json!(tx_hash)];
        let result = self.call_rpc("eth_getTransactionByHash", params).await?;

        if result.is_null() {
            return Err(anyhow!("Transaction {} not found", tx_hash));
        }

        let tx: Transaction = serde_json::from_value(result)?;
        Ok(tx)
    }

    pub async fn get_transaction_receipt(&self, tx_hash: &str) -> Result<TransactionReceipt> {
        let params = vec![json!(tx_hash)];
        let result = self.call_rpc("eth_getTransactionReceipt", params).await?;

        if result.is_null() {
            return Err(anyhow!("Transaction receipt {} not found", tx_hash));
        }

        let receipt: TransactionReceipt = serde_json::from_value(result)?;
        Ok(receipt)
    }

    pub async fn get_balance(&self, address: Address) -> Result<U256> {
        let address_str = format!("0x{:x}", address);
        let params = vec![
            json!(address_str),
            json!("latest"),
        ];

        let result = self.call_rpc("eth_getBalance", params).await?;
        let balance_hex = result.as_str()
            .ok_or_else(|| anyhow!("Invalid balance response"))?;

        let balance = U256::from_str_radix(balance_hex.trim_start_matches("0x"), 16)?;
        Ok(balance)
    }

    pub async fn call_contract(&self, to: Address, data: &str) -> Result<String> {
        let to_str = format!("0x{:x}", to);
        let call_data = json!({
            "to": to_str,
            "data": data,
        });

        let params = vec![
            call_data,
            json!("latest"),
        ];

        let result = self.call_rpc("eth_call", params).await?;
        let result_str = result.as_str()
            .ok_or_else(|| anyhow!("Invalid call response"))?;

        Ok(result_str.to_string())
    }

}
