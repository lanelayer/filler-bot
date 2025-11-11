//! MuSig2 and Taproot utility functions
//! 
//! Vendored from wasm-helper to make filler-bot self-contained

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::{Address, Amount, Network, OutPoint, ScriptBuf, XOnlyPublicKey as BitcoinXOnly, taproot};
use bitcoin::opcodes::all as op;
use bitcoin::psbt::Psbt;
use bitcoin::{Transaction, TxIn, TxOut, Witness, Sequence, absolute};
use bitcoin::sighash::{SighashCache, TapSighashType, Prevouts};
use secp256k1::musig::KeyAggCache;
use secp256k1::{PublicKey, Scalar, Secp256k1, XOnlyPublicKey};

pub type Result<T> = std::result::Result<T, String>;

// ============================================================================
// Key Aggregation
// ============================================================================

/// Aggregate public keys using MuSig2
pub fn aggregate_pubkeys(pubkeys: &[PublicKey]) -> KeyAggCache {
    let refs: Vec<&PublicKey> = pubkeys.iter().collect();
    KeyAggCache::new(&refs)
}

// ============================================================================
// Refund Leaf Script
// ============================================================================

/// Create a CSV refund leaf script: <Δ> CSV DROP <UserXOnly> CHECKSIG
/// 
/// This allows the user to unilaterally refund after Δ blocks using only their key.
pub fn refund_leaf_script(user_x: XOnlyPublicKey, csv_delta_blocks: u32) -> ScriptBuf {
    bitcoin::script::Builder::new()
        .push_int(i64::from(csv_delta_blocks))
        .push_opcode(op::OP_CSV)
        .push_opcode(op::OP_DROP)
        .push_slice(&user_x.serialize())
        .push_opcode(op::OP_CHECKSIG)
        .into_script()
}

// ============================================================================
// Taproot Address Building
// ============================================================================

/// Taproot address with refund leaf
pub struct TrWithRefund {
    pub address: Address,
    pub output_key: XOnlyPublicKey,
    pub internal_key: XOnlyPublicKey,
    pub control_block_refund: taproot::ControlBlock,
    pub refund_leaf: taproot::TapLeafHash,
    pub refund_script: ScriptBuf,
    pub merkle_root: Option<taproot::TapNodeHash>,
}

/// Build Taproot address with key-path=P_agg (MuSig2) and one refund leaf (CSV)
pub fn build_tr_with_refund_leaf(
    _secp: &Secp256k1<secp256k1::All>,
    agg_x: XOnlyPublicKey,
    refund_script: ScriptBuf,
    network: Network,
) -> Result<TrWithRefund> {
    // Create taproot builder with refund leaf
    let builder = taproot::TaprootBuilder::new()
        .add_leaf(0, refund_script.clone())
        .map_err(|e| format!("Failed to add leaf: {:?}", e))?;
    
    // Convert to bitcoin XOnlyPublicKey
    let btc_xonly = BitcoinXOnly::from_slice(&agg_x.serialize())
        .map_err(|e| format!("Invalid agg key: {}", e))?;
    
    // Create a bitcoin secp256k1 context for finalize
    let btc_secp = bitcoin::secp256k1::Secp256k1::verification_only();
    
    // Finalize taproot tree
    let spend_info = builder
        .finalize(&btc_secp, btc_xonly)
        .map_err(|e| format!("Failed to finalize taproot: {:?}", e))?;
    
    let output_key_btc = spend_info.output_key();
    let address = Address::p2tr_tweaked(output_key_btc, network);
    let merkle_root = spend_info.merkle_root();
    
    // Get control block for the refund leaf
    let leaf_hash = taproot::TapLeafHash::from_script(&refund_script, taproot::LeafVersion::TapScript);
    let control_block_refund = spend_info
        .control_block(&(refund_script.clone(), taproot::LeafVersion::TapScript))
        .ok_or("Failed to get control block")?;
    
    // Convert output key back to secp256k1 XOnlyPublicKey
    let output_key_bytes: [u8; 32] = output_key_btc.to_x_only_public_key().serialize();
    let output_key = XOnlyPublicKey::from_byte_array(output_key_bytes)
        .map_err(|e| format!("Invalid output key: {:?}", e))?;
    
    Ok(TrWithRefund {
        address,
        output_key,
        internal_key: agg_x,
        control_block_refund,
        refund_leaf: leaf_hash,
        refund_script,
        merkle_root,
    })
}

// ============================================================================
// Transaction Building
// ============================================================================

fn op_return(payload: &[u8]) -> ScriptBuf {
    use bitcoin::script::PushBytesBuf;
    let mut push_bytes = PushBytesBuf::new();
    push_bytes.extend_from_slice(payload).expect("push bytes");
    
    bitcoin::script::Builder::new()
        .push_opcode(op::OP_RETURN)
        .push_slice(push_bytes)
        .into_script()
}

/// Build a burn transaction with P2WSH output and OP_RETURN metadata
pub fn build_burn_psbt(
    funding_outpoint: OutPoint,
    funding_value: Amount,
    burn_amount: Amount,
    opret_payload: &[u8],
    network: Network,
) -> Result<Psbt> {
    let txin = TxIn {
        previous_output: funding_outpoint,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    };

    // Create P2WSH burn output
    let burn_script = op_return(opret_payload);
    let p2wsh_address = Address::p2wsh(&burn_script, network);
    
    let burn_output = TxOut {
        value: burn_amount,
        script_pubkey: p2wsh_address.script_pubkey(),
    };

    // OP_RETURN metadata output
    let opret_output = TxOut {
        value: Amount::ZERO,
        script_pubkey: burn_script,
    };

    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![txin],
        output: vec![burn_output, opret_output],
    };

    let mut psbt = Psbt::from_unsigned_tx(tx).map_err(|e| format!("PSBT error: {}", e))?;

    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: funding_value,
        script_pubkey: ScriptBuf::new(),
    });

    Ok(psbt)
}

/// Build a payout transaction (cooperative key-path spend)
pub fn build_payout_psbt(
    funding_outpoint: OutPoint,
    funding_value: Amount,
    payout_spk: ScriptBuf,
    payout_value: Amount,
) -> Result<Psbt> {
    let txin = TxIn {
        previous_output: funding_outpoint,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    };

    let txout = TxOut {
        value: payout_value,
        script_pubkey: payout_spk,
    };

    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![txin],
        output: vec![txout],
    };

    let mut psbt = Psbt::from_unsigned_tx(tx).map_err(|e| format!("PSBT error: {}", e))?;

    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: funding_value,
        script_pubkey: ScriptBuf::new(),
    });

    Ok(psbt)
}

// ============================================================================
// Sighash Computation
// ============================================================================

/// Compute BIP-341 key-path sighash for taproot key-spend
pub fn keyspend_sighash(
    psbt: &Psbt,
    prevout: &TxOut,
    sighash_ty: TapSighashType,
) -> Result<[u8; 32]> {
    let tx = &psbt.unsigned_tx;
    let mut cache = SighashCache::new(tx);
    
    let hash = cache
        .taproot_key_spend_signature_hash(
            0, 
            &Prevouts::All(&[prevout.clone()]), 
            sighash_ty
        )
        .map_err(|e| format!("Key-path sighash error: {}", e))?;
    
    Ok(*hash.as_byte_array())
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::Secp256k1;
    use secp256k1::Keypair;

    #[test]
    fn test_aggregate_pubkeys() {
        let mut rng = secp256k1::rand::rng();
        let kp1 = Keypair::new(&mut rng);
        let kp2 = Keypair::new(&mut rng);
        
        let pk1 = PublicKey::from_keypair(&kp1);
        let pk2 = PublicKey::from_keypair(&kp2);
        
        let cache = aggregate_pubkeys(&[pk1, pk2]);
        let _agg_pk = cache.agg_pk();
    }

    #[test]
    fn test_refund_leaf_script() {
        let mut rng = secp256k1::rand::rng();
        let kp = Keypair::new(&mut rng);
        let (xonly, _) = kp.x_only_public_key();
        
        let script = refund_leaf_script(xonly, 144);
        assert!(!script.is_empty());
    }

    #[test]
    fn test_build_tr_with_refund_leaf() {
        let secp = Secp256k1::new();
        let mut rng = secp256k1::rand::rng();
        
        let kp1 = Keypair::new(&mut rng);
        let kp2 = Keypair::new(&mut rng);
        
        let pk1 = PublicKey::from_keypair(&kp1);
        let pk2 = PublicKey::from_keypair(&kp2);
        
        let cache = aggregate_pubkeys(&[pk1, pk2]);
        let agg_x = cache.agg_pk();
        
        let (user_x, _) = kp1.x_only_public_key();
        let refund_script = refund_leaf_script(user_x, 144);
        
        let tr = build_tr_with_refund_leaf(&secp, agg_x, refund_script, Network::Regtest);
        assert!(tr.is_ok());
        assert!(tr.unwrap().address.to_string().starts_with("bcrt1p"));
    }

    #[test]
    fn test_build_burn_psbt() {
        let outpoint = OutPoint {
            txid: bitcoin::Txid::all_zeros(),
            vout: 0,
        };

        let psbt = build_burn_psbt(
            outpoint,
            Amount::from_sat(20_000),
            Amount::from_sat(19_000),
            b"BTI1\x00\x00\x00\x01deadbeefdeadbeefdeadbeef",
            Network::Regtest,
        );
        
        assert!(psbt.is_ok());
        let psbt = psbt.unwrap();
        assert_eq!(psbt.unsigned_tx.input.len(), 1);
        assert_eq!(psbt.unsigned_tx.output.len(), 2);
    }

    #[test]
    fn test_build_payout_psbt() {
        let outpoint = OutPoint {
            txid: bitcoin::Txid::all_zeros(),
            vout: 0,
        };

        let spk = ScriptBuf::new();
        let psbt = build_payout_psbt(
            outpoint,
            Amount::from_sat(20_000),
            spk,
            Amount::from_sat(18_000),
        );
        
        assert!(psbt.is_ok());
        let psbt = psbt.unwrap();
        assert_eq!(psbt.unsigned_tx.input.len(), 1);
        assert_eq!(psbt.unsigned_tx.output.len(), 1);
    }
}


