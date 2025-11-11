use alloy_primitives::{keccak256, Address, B256, U256};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

const EIP712_DOMAIN_TYPE: &[u8] =
    b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
const CREATE_INTENT_TYPE: &[u8] = b"CreateIntent(bytes intent,uint256 nonce,uint256 value)";

#[derive(Debug, Clone)]
pub struct Eip712Domain {
    pub name: String,
    pub version: String,
    pub chain_id: u64,
    pub verifying_contract: Address,
}

impl From<&serde_json::Value> for Eip712Domain {
    fn from(value: &serde_json::Value) -> Self {
        let chain_id = value["chainId"]
            .as_u64()
            .or_else(|| value["chainId"].as_str().and_then(|s| s.parse().ok()))
            .unwrap_or(1281453634);

        let verifying_contract = value["verifyingContract"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| {
                Address::from_str("0x0000000000000000000000000000000000000045").unwrap()
            });

        Self {
            name: value["name"]
                .as_str()
                .unwrap_or("CoreLaneIntent")
                .to_string(),
            version: value["version"].as_str().unwrap_or("1").to_string(),
            chain_id,
            verifying_contract,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateIntentMessage {
    pub intent: String,
    pub nonce: String,
    pub value: String,
}

pub fn eip712_digest(domain: &Eip712Domain, intent: &[u8], nonce: U256, value: U256) -> B256 {
    let domain_sep = domain_separator(domain);
    let struct_hash = create_intent_struct_hash(intent, nonce, value);
    eip712_digest_from_hashes(domain_sep, struct_hash)
}

fn domain_separator(domain: &Eip712Domain) -> B256 {
    let domain_type_hash = keccak256(EIP712_DOMAIN_TYPE);
    let name_hash = keccak256(domain.name.as_bytes());
    let version_hash = keccak256(domain.version.as_bytes());

    let mut domain_blob = Vec::new();
    domain_blob.extend_from_slice(domain_type_hash.as_slice());
    domain_blob.extend_from_slice(name_hash.as_slice());
    domain_blob.extend_from_slice(version_hash.as_slice());
    let mut chain_id_bytes = [0u8; 32];
    chain_id_bytes[24..].copy_from_slice(&domain.chain_id.to_be_bytes());
    domain_blob.extend_from_slice(&chain_id_bytes);
    let mut addr_bytes = [0u8; 32];
    addr_bytes[12..].copy_from_slice(domain.verifying_contract.as_slice());
    domain_blob.extend_from_slice(&addr_bytes);
    keccak256(domain_blob)
}

fn create_intent_struct_hash(intent: &[u8], nonce: U256, value: U256) -> B256 {
    let message_type_hash = keccak256(CREATE_INTENT_TYPE);
    let intent_hash = keccak256(intent);
    let mut msg_blob = Vec::new();
    msg_blob.extend_from_slice(message_type_hash.as_slice());
    msg_blob.extend_from_slice(intent_hash.as_slice());
    let nonce_bytes: [u8; 32] = nonce.to_be_bytes();
    msg_blob.extend_from_slice(&nonce_bytes);
    let value_bytes: [u8; 32] = value.to_be_bytes();
    msg_blob.extend_from_slice(&value_bytes);
    keccak256(msg_blob)
}

fn eip712_digest_from_hashes(domain_sep: B256, struct_hash: B256) -> B256 {
    let mut preimage = Vec::with_capacity(66);
    preimage.push(0x19);
    preimage.push(0x01);
    preimage.extend_from_slice(domain_sep.as_slice());
    preimage.extend_from_slice(struct_hash.as_slice());
    keccak256(preimage)
}

pub fn recover_signer_from_digest(digest: &B256, sig: &[u8]) -> Result<Address> {
    use alloy_primitives::Signature;
    Signature::try_from(sig)
        .map_err(|e| anyhow!("Invalid signature format: {}", e))?
        .recover_address_from_prehash(digest)
        .map_err(|e| anyhow!("Failed to recover address: {}", e))
}

pub fn verify_eip712_signature(
    domain: &Eip712Domain,
    intent: &[u8],
    nonce: U256,
    value: U256,
    signature: &[u8],
) -> Result<Address> {
    let digest = eip712_digest(domain, intent, nonce, value);
    recover_signer_from_digest(&digest, signature)
}
