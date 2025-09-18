use anyhow::Result;
use alloy_primitives::U256;
use ciborium::{from_reader, into_writer};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::io::Cursor;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum IntentType {
    AnchorBitcoinFill = 1,
}

impl From<u8> for IntentType {
    fn from(value: u8) -> Self {
        match value {
            1 => IntentType::AnchorBitcoinFill,
            _ => panic!("Invalid intent type: {}", value),
        }
    }
}

impl From<IntentType> for u8 {
    fn from(intent_type: IntentType) -> Self {
        intent_type as u8
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentData {
    pub intent_type: IntentType,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorBitcoinFill {
    pub bitcoin_address: Vec<u8>,
    pub amount: U256,
    pub max_fee: U256,
    pub expire_by: u64,
}

impl IntentData {
    pub fn from_cbor(cbor_bytes: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(cbor_bytes);
        let intent_data: IntentData = from_reader(&mut cursor)?;
        Ok(intent_data)
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        into_writer(&self, &mut buffer)?;
        Ok(buffer)
    }

    pub fn parse_anchor_bitcoin_fill(&self) -> Result<AnchorBitcoinFill> {
        if self.intent_type != IntentType::AnchorBitcoinFill {
            return Err(anyhow::anyhow!("Expected AnchorBitcoinFill intent type"));
        }

        let mut cursor = Cursor::new(&self.data);
        let fill_data: AnchorBitcoinFill = from_reader(&mut cursor)?;
        Ok(fill_data)
    }
}

impl AnchorBitcoinFill {
    pub fn from_cbor(cbor_bytes: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(cbor_bytes);
        let fill_data: AnchorBitcoinFill = from_reader(&mut cursor)?;
        Ok(fill_data)
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        into_writer(&self, &mut buffer)?;
        Ok(buffer)
    }

    pub fn parse_bitcoin_address(&self) -> Result<String> {
        let address_str = bs58::encode(&self.bitcoin_address).into_string();

        use bitcoin::Address;
        let _address = Address::from_str(&address_str)?;

        Ok(address_str)
    }

    pub fn from_bitcoin_address(
        bitcoin_address: &str,
        amount: U256,
        max_fee: U256,
        expire_by: u64,
    ) -> Result<Self> {
        let address_bytes = bs58::decode(bitcoin_address).into_vec()?;

        Ok(AnchorBitcoinFill {
            bitcoin_address: address_bytes,
            amount,
            max_fee,
            expire_by,
        })
    }
}

pub fn create_anchor_bitcoin_fill_intent(
    bitcoin_address: &str,
    amount: U256,
    max_fee: U256,
    expire_by: u64,
) -> Result<IntentData> {
    let fill_data = AnchorBitcoinFill::from_bitcoin_address(bitcoin_address, amount, max_fee, expire_by)?;
    let fill_cbor = fill_data.to_cbor()?;

    Ok(IntentData {
        intent_type: IntentType::AnchorBitcoinFill,
        data: fill_cbor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;

    #[test]
    fn test_intent_type_conversion() {
        assert_eq!(IntentType::AnchorBitcoinFill as u8, 1);
        assert_eq!(IntentType::from(1), IntentType::AnchorBitcoinFill);
    }

    #[test]
    fn test_anchor_bitcoin_fill_cbor_roundtrip() {
        let original = AnchorBitcoinFill {
            bitcoin_address: vec![1, 2, 3, 4, 5],
            amount: U256::from(1000),
            max_fee: U256::from(100),
            expire_by: 1234567890,
        };

        let cbor_bytes = original.to_cbor().unwrap();
        let decoded = AnchorBitcoinFill::from_cbor(&cbor_bytes).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_intent_data_cbor_roundtrip() {
        let fill_data = AnchorBitcoinFill {
            bitcoin_address: vec![1, 2, 3, 4, 5],
            amount: U256::from(1000),
            max_fee: U256::from(100),
            expire_by: 1234567890,
        };

        let fill_cbor = fill_data.to_cbor().unwrap();
        let intent_data = IntentData {
            intent_type: IntentType::AnchorBitcoinFill,
            data: fill_cbor,
        };

        let cbor_bytes = intent_data.to_cbor().unwrap();
        let decoded = IntentData::from_cbor(&cbor_bytes).unwrap();

        assert_eq!(intent_data, decoded);
    }

    #[test]
    fn test_bitcoin_address_parsing() {
        let test_address = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";

        let fill_data = AnchorBitcoinFill::from_bitcoin_address(
            test_address,
            U256::from(1000),
            U256::from(100),
            1234567890,
        ).unwrap();

        let parsed_address = fill_data.parse_bitcoin_address().unwrap();
        assert_eq!(parsed_address, test_address);
    }

    #[test]
    fn test_create_anchor_bitcoin_fill_intent() {
        let test_address = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
        let amount = U256::from(1000);
        let max_fee = U256::from(100);
        let expire_by = 1234567890;

        let intent_data = create_anchor_bitcoin_fill_intent(
            test_address,
            amount,
            max_fee,
            expire_by,
        ).unwrap();

        assert_eq!(intent_data.intent_type, IntentType::AnchorBitcoinFill);

        let fill_data = intent_data.parse_anchor_bitcoin_fill().unwrap();
        assert_eq!(fill_data.amount, amount);
        assert_eq!(fill_data.max_fee, max_fee);
        assert_eq!(fill_data.expire_by, expire_by);

        let parsed_address = fill_data.parse_bitcoin_address().unwrap();
        assert_eq!(parsed_address, test_address);
    }
}
