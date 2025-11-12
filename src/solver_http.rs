//! HTTP API for MuSig2 solver operations
//!
//! Provides endpoints for browser clients to interact with the solver
//! for BTC → LaneBTC swap operations using MuSig2 signatures

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use crate::intent_system::{CoreLaneIntentSystem, IntentSystem, LockData};
use crate::intent_types::IntentData;
use ciborium::from_reader;
use std::io::Cursor;
use alloy_primitives::{Address, Bytes};
use crate::intent_contract::calculate_intent_id;
use crate::eip712::{verify_eip712_signature, Eip712Domain};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tower_http::cors::CorsLayer;
use tracing::{error, info, warn};

use secp256k1::{Keypair, PublicKey, Secp256k1};
use secp256k1::musig::{
    AggregatedNonce, KeyAggCache, PartialSignature, PublicNonce, SecretNonce, Session,
    SessionSecretRand,
};
use bitcoin::hashes::Hash;
use alloy_primitives::{Address as AlloyAddress, U256};
use std::str::FromStr;

use crate::musig_utils;

type SessionId = String;

// Core Lane RPC URL - should be configurable
const CORE_LANE_RPC: &str = "http://127.0.0.1:8545";

// ============================================================================
// Data Structures
// ============================================================================

#[derive(Clone, Serialize, Deserialize)]
pub struct QuoteRequest {
    btc_amount: f64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct QuoteResponse {
    solver: String,
    solver_pubkey: String,
    fee: f64,
    receives: f64,
    timelock: u32,
    reputation: u8,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EscrowInitRequest {
    user_pubkey: String,
    btc_amount: f64,
    intent_hash: String,
    user_address: Option<String>,  // User's Core Lane address for receiving laneBTC
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EscrowInitResponse {
    session_id: String,
    solver_pubkey: String,
    address_info: AddressInfo,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AddressInfo {
    address: String,
    agg_pubkey: String,
    output_key: String,
    merkle_root_hex: String,
    internal_key: String,
    csv_delta: u32,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct NonceRequest {
    session_id: String,
    user_pub_nonce: String,
    psbt_hex: String,
    sighash_hex: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct NonceResponse {
    solver_pub_nonce: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SignRequest {
    session_id: String,
    user_partial_sig: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SignResponse {
    final_sig: String,
    signed_tx_hex: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BuildBurnRequest {
    session_id: String,
    funding_txid: String,
    funding_vout: u32,
    funding_value_sats: u64,
    burn_amount_sats: u64,
    chain_id: u32,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BuildBurnResponse {
    psbt_hex: String,
    sighash_hex: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BuildPayoutRequest {
    session_id: String,
    funding_txid: String,
    funding_vout: u32,
    funding_value_sats: u64,
    payout_address: String,
    payout_amount_sats: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BuildPayoutResponse {
    psbt_hex: String,
    sighash_hex: String,
}

// ============================================================================
// Solver State
// ============================================================================

struct NonceState {
    solver_sec_nonce: Option<SecretNonce>,
    solver_pub_nonce: Option<PublicNonce>,
    user_pub_nonce: Option<PublicNonce>,
    sighash: Option<[u8; 32]>,
    psbt_hex: Option<String>,
}

struct SessionData {
    user_pk: PublicKey,
    solver_kp: Keypair,
    intent_hash: String,
    btc_amount: f64,
    merkle_root: Option<Vec<u8>>,
    key_agg_cache_untweaked: KeyAggCache,
    burn_nonce_state: Option<NonceState>,
    payout_nonce_state: Option<NonceState>,
    signed_burn_tx: Option<String>,
    signed_payout_tx: Option<String>,
    escrow_address: Option<String>,           // The 2-of-2 multisig address
    lanebtc_sent: bool,                       // Track if we've sent laneBTC
    user_core_lane_address: Option<String>,   // User's Core Lane address for sending laneBTC
}

#[derive(Clone)]
pub struct SolverState {
    sessions: Arc<Mutex<HashMap<SessionId, SessionData>>>,
    secp: Secp256k1<secp256k1::All>,
    intent_system: Arc<CoreLaneIntentSystem>,
}

impl SolverState {
    pub fn new(intent_system: Arc<CoreLaneIntentSystem>) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            secp: Secp256k1::new(),
            intent_system
        }
    }

}

// ============================================================================
// API Handlers
// ============================================================================

async fn health_check() -> &'static str {
    "LaneLayer Solver - Ready"
}

async fn get_quote(Json(req): Json<QuoteRequest>) -> Json<QuoteResponse> {
    let fee = 0.0001;
    let receives = req.btc_amount - fee;

    let mut rng = secp256k1::rand::rng();
    let kp = Keypair::new(&mut rng);
    let pk = PublicKey::from_keypair(&kp);

    Json(QuoteResponse {
        solver: "LaneLayer".to_string(),
        solver_pubkey: hex::encode(pk.serialize()),
        fee,
        receives,
        timelock: 144,
        reputation: 100,
    })
}

async fn init_escrow(
    State(state): State<SolverState>,
    Json(req): Json<EscrowInitRequest>,
) -> Result<Json<EscrowInitResponse>, StatusCode> {
    info!("📥 Escrow init request:");
    info!("   User pubkey: {}", req.user_pubkey);
    info!("   Amount: {} BTC", req.btc_amount);
    info!("   Intent hash: {}", req.intent_hash);

    let user_pk_bytes = hex::decode(&req.user_pubkey).map_err(|_| StatusCode::BAD_REQUEST)?;
    let user_pk = PublicKey::from_slice(&user_pk_bytes).map_err(|_| StatusCode::BAD_REQUEST)?;

    let mut rng = secp256k1::rand::rng();
    let solver_kp = Keypair::new(&mut rng);
    let solver_pk = PublicKey::from_keypair(&solver_kp);

    info!("   Generated solver keypair");
    info!("   Solver pubkey: {}", hex::encode(solver_pk.serialize()));

    let key_agg_cache = musig_utils::aggregate_pubkeys(&[user_pk, solver_pk]);
    let agg_x = key_agg_cache.agg_pk();

    let (user_xonly, _) = user_pk.x_only_public_key();
    let refund_script = musig_utils::refund_leaf_script(user_xonly, 144);

    let tr = musig_utils::build_tr_with_refund_leaf(
        &state.secp,
        agg_x,
        refund_script,
        bitcoin::Network::Regtest,
    )
    .map_err(|e| {
        error!("Error building address: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let merkle_root_bytes = tr.merkle_root.map(|r| r.as_byte_array().to_vec());
    let merkle_root_hex = if let Some(ref root_bytes) = merkle_root_bytes {
        hex::encode(root_bytes)
    } else {
        String::new()
    };

    let address_info = AddressInfo {
        address: tr.address.to_string(),
        agg_pubkey: hex::encode(agg_x.serialize()),
        output_key: hex::encode(tr.output_key.serialize()),
        merkle_root_hex,
        internal_key: hex::encode(agg_x.serialize()),
        csv_delta: 144,
    };

    let session_id = format!("{:x}", rand::random::<u64>());

    let session_data = SessionData {
        user_pk,
        solver_kp,
        intent_hash: req.intent_hash,
        btc_amount: req.btc_amount,
        merkle_root: merkle_root_bytes,
        key_agg_cache_untweaked: key_agg_cache,
        burn_nonce_state: None,
        payout_nonce_state: None,
        signed_burn_tx: None,
        signed_payout_tx: None,
        escrow_address: Some(address_info.address.clone()),
        lanebtc_sent: false,
        user_core_lane_address: req.user_address,
    };

    state
        .sessions
        .lock()
        .unwrap()
        .insert(session_id.clone(), session_data);

    info!("✅ Session created: {}", session_id);
    info!("   Address: {}", address_info.address);

    Ok(Json(EscrowInitResponse {
        session_id,
        solver_pubkey: hex::encode(solver_pk.serialize()),
        address_info,
    }))
}

fn apply_taproot_tweak(
    key_agg_cache: &mut KeyAggCache,
    merkle_bytes: &[u8],
) -> Result<(), StatusCode> {
    use bitcoin::hashes::{sha256, HashEngine};
    use secp256k1::Scalar;

    let mut eng = sha256::Hash::engine();
    let tag = b"TapTweak";
    let tag_hash = sha256::Hash::hash(tag);
    eng.input(tag_hash.as_ref());
    eng.input(tag_hash.as_ref());
    eng.input(&key_agg_cache.agg_pk().serialize());
    eng.input(merkle_bytes);
    let tweak_hash = sha256::Hash::from_engine(eng);
    let tweak_scalar = Scalar::from_be_bytes(tweak_hash.to_byte_array())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    key_agg_cache
        .pubkey_xonly_tweak_add(&tweak_scalar)
        .map_err(|e| {
            error!("Failed to apply taproot tweak: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(())
}

async fn exchange_burn_nonce(
    State(state): State<SolverState>,
    Json(req): Json<NonceRequest>,
) -> Result<Json<NonceResponse>, StatusCode> {
    info!("📥 [BURN] Nonce exchange request:");
    info!("   Session: {}", req.session_id);

    let mut sessions = state.sessions.lock().unwrap();
    let session = sessions
        .get_mut(&req.session_id)
        .ok_or(StatusCode::NOT_FOUND)?;

    let user_nonce_bytes = hex::decode(&req.user_pub_nonce).map_err(|_| StatusCode::BAD_REQUEST)?;
    if user_nonce_bytes.len() != 66 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut nonce_arr = [0u8; 66];
    nonce_arr.copy_from_slice(&user_nonce_bytes);
    let user_pub_nonce =
        PublicNonce::from_byte_array(&nonce_arr).map_err(|_| StatusCode::BAD_REQUEST)?;

    let sighash_bytes = hex::decode(&req.sighash_hex).map_err(|_| StatusCode::BAD_REQUEST)?;
    if sighash_bytes.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut sighash = [0u8; 32];
    sighash.copy_from_slice(&sighash_bytes);

    info!("   Sighash: {}", req.sighash_hex);

    let mut rng = secp256k1::rand::rng();
    let session_rand = SessionSecretRand::from_rng(&mut rng);

    let mut key_agg_cache = session.key_agg_cache_untweaked.clone();

    if let Some(ref merkle_bytes) = session.merkle_root {
        info!("   Applying taproot tweak with merkle root");
        apply_taproot_tweak(&mut key_agg_cache, merkle_bytes)?;
        info!(
            "   Taproot tweak applied, agg_pk: {}",
            hex::encode(key_agg_cache.agg_pk().serialize())
        );
    }

    let (solver_sec_nonce, solver_pub_nonce) =
        key_agg_cache.nonce_gen(session_rand, session.solver_kp.public_key(), &sighash, None);

    info!("   Generated solver nonce");

    session.burn_nonce_state = Some(NonceState {
        solver_sec_nonce: Some(solver_sec_nonce),
        solver_pub_nonce: Some(solver_pub_nonce),
        user_pub_nonce: Some(user_pub_nonce),
        sighash: Some(sighash),
        psbt_hex: Some(req.psbt_hex.clone()),
    });

    Ok(Json(NonceResponse {
        solver_pub_nonce: hex::encode(solver_pub_nonce.serialize()),
    }))
}

async fn exchange_payout_nonce(
    State(state): State<SolverState>,
    Json(req): Json<NonceRequest>,
) -> Result<Json<NonceResponse>, StatusCode> {
    info!("📥 [PAYOUT] Nonce exchange request:");
    info!("   Session: {}", req.session_id);

    let mut sessions = state.sessions.lock().unwrap();
    let session = sessions
        .get_mut(&req.session_id)
        .ok_or(StatusCode::NOT_FOUND)?;

    let user_nonce_bytes = hex::decode(&req.user_pub_nonce).map_err(|_| StatusCode::BAD_REQUEST)?;
    if user_nonce_bytes.len() != 66 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut nonce_arr = [0u8; 66];
    nonce_arr.copy_from_slice(&user_nonce_bytes);
    let user_pub_nonce =
        PublicNonce::from_byte_array(&nonce_arr).map_err(|_| StatusCode::BAD_REQUEST)?;

    let sighash_bytes = hex::decode(&req.sighash_hex).map_err(|_| StatusCode::BAD_REQUEST)?;
    if sighash_bytes.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut sighash = [0u8; 32];
    sighash.copy_from_slice(&sighash_bytes);

    info!("   Sighash: {}", req.sighash_hex);

    let mut rng = secp256k1::rand::rng();
    let session_rand = SessionSecretRand::from_rng(&mut rng);

    let mut key_agg_cache = session.key_agg_cache_untweaked.clone();

    if let Some(ref merkle_bytes) = session.merkle_root {
        info!("   Applying taproot tweak with merkle root");
        apply_taproot_tweak(&mut key_agg_cache, merkle_bytes)?;
        info!(
            "   Taproot tweak applied, agg_pk: {}",
            hex::encode(key_agg_cache.agg_pk().serialize())
        );
    }

    let (solver_sec_nonce, solver_pub_nonce) =
        key_agg_cache.nonce_gen(session_rand, session.solver_kp.public_key(), &sighash, None);

    info!("   Generated solver nonce");

    session.payout_nonce_state = Some(NonceState {
        solver_sec_nonce: Some(solver_sec_nonce),
        solver_pub_nonce: Some(solver_pub_nonce),
        user_pub_nonce: Some(user_pub_nonce),
        sighash: Some(sighash),
        psbt_hex: Some(req.psbt_hex.clone()),
    });

    Ok(Json(NonceResponse {
        solver_pub_nonce: hex::encode(solver_pub_nonce.serialize()),
    }))
}

async fn partial_sign_burn(
    State(state): State<SolverState>,
    Json(req): Json<SignRequest>,
) -> Result<Json<SignResponse>, StatusCode> {
    info!("📥 [BURN] Partial sign request:");
    info!("   Session: {}", req.session_id);
    info!("   User partial sig: {}", &req.user_partial_sig[..16]);

    let mut sessions = state.sessions.lock().unwrap();
    let session = sessions.get_mut(&req.session_id).ok_or_else(|| {
        error!("❌ Session not found: {}", req.session_id);
        StatusCode::NOT_FOUND
    })?;

    let user_partial_bytes = hex::decode(&req.user_partial_sig).map_err(|_| StatusCode::BAD_REQUEST)?;
    if user_partial_bytes.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut partial_arr = [0u8; 32];
    partial_arr.copy_from_slice(&user_partial_bytes);
    let user_partial =
        PartialSignature::from_byte_array(&partial_arr).map_err(|_| StatusCode::BAD_REQUEST)?;

    let mut burn_state = session.burn_nonce_state.take().ok_or_else(|| {
        error!("❌ Burn nonce state not found");
        StatusCode::BAD_REQUEST
    })?;

    let user_pub_nonce = burn_state
        .user_pub_nonce
        .take()
        .ok_or(StatusCode::BAD_REQUEST)?;
    let solver_pub_nonce = burn_state
        .solver_pub_nonce
        .take()
        .ok_or(StatusCode::BAD_REQUEST)?;
    let sighash = burn_state.sighash.take().ok_or(StatusCode::BAD_REQUEST)?;
    let solver_sec_nonce = burn_state
        .solver_sec_nonce
        .take()
        .ok_or(StatusCode::BAD_REQUEST)?;
    let psbt_hex = burn_state.psbt_hex.take().ok_or(StatusCode::BAD_REQUEST)?;

    let solver_kp = session.solver_kp.clone();

    let mut key_agg_cache = session.key_agg_cache_untweaked.clone();
    if let Some(ref merkle_bytes) = session.merkle_root {
        apply_taproot_tweak(&mut key_agg_cache, merkle_bytes)?;
    }

    info!("   All session data retrieved successfully");

    let agg_nonce = AggregatedNonce::new(&[&user_pub_nonce, &solver_pub_nonce]);
    let musig_session = Session::new(&key_agg_cache, agg_nonce, &sighash);
    let solver_partial = musig_session.partial_sign(solver_sec_nonce, &solver_kp, &key_agg_cache);

    info!("   Generated solver partial signature");

    let agg_sig = musig_session.partial_sig_agg(&[&user_partial, &solver_partial]);
    let final_sig = agg_sig.verify(&key_agg_cache.agg_pk(), &sighash).map_err(|e| {
        error!("Signature verification failed: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let sig_bytes: [u8; 64] = *final_sig.as_ref();

    info!("✅ [BURN] Final signature created and verified");

    let tx_bytes = hex::decode(&psbt_hex).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut tx: bitcoin::Transaction =
        bitcoin::consensus::deserialize(&tx_bytes).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut witness_data = sig_bytes.to_vec();
    witness_data.push(0x81);
    tx.input[0].witness = bitcoin::Witness::from_slice(&[&witness_data]);

    let signed_tx_hex = hex::encode(bitcoin::consensus::serialize(&tx));

    session.signed_burn_tx = Some(signed_tx_hex.clone());

    info!("   Stored signed burn tx ({} bytes)", signed_tx_hex.len() / 2);

    // Auto-collaborate: Send laneBTC to user now that we have the signed burn tx as insurance
    let escrow_address = session.escrow_address.clone();
    let user_address = session.user_core_lane_address.clone();
    let btc_amount = session.btc_amount;
    let lanebtc_sent = session.lanebtc_sent;
    let session_id = req.session_id.clone();

    // Drop the lock before async operations
    drop(sessions);

    if !lanebtc_sent {
        if let (Some(escrow_addr), Some(user_addr)) = (escrow_address, user_address) {
            info!("🤖 Auto-collaboration: Checking escrow and sending laneBTC...");
            
            // Spawn background task to send laneBTC
            let state_clone = state.clone();
            tokio::spawn(async move {
                if let Err(e) = send_lanebtc_to_user(
                    &state_clone,
                    &session_id,
                    &escrow_addr,
                    &user_addr,
                    btc_amount,
                ).await {
                    error!("Failed to send laneBTC: {}", e);
                } else {
                    info!("✅ LaneBTC sent to user successfully");
                }
            });
        } else {
            warn!("⚠️  Cannot auto-collaborate: missing escrow address or user address");
        }
    }

    Ok(Json(SignResponse {
        final_sig: hex::encode(sig_bytes),
        signed_tx_hex,
    }))
}

async fn partial_sign_payout(
    State(state): State<SolverState>,
    Json(req): Json<SignRequest>,
) -> Result<Json<SignResponse>, StatusCode> {
    info!("📥 [PAYOUT] Partial sign request:");
    info!("   Session: {}", req.session_id);
    info!("   User partial sig: {}", &req.user_partial_sig[..16]);

    let mut sessions = state.sessions.lock().unwrap();
    let session = sessions.get_mut(&req.session_id).ok_or_else(|| {
        error!("❌ Session not found: {}", req.session_id);
        StatusCode::NOT_FOUND
    })?;

    let user_partial_bytes = hex::decode(&req.user_partial_sig).map_err(|_| StatusCode::BAD_REQUEST)?;
    if user_partial_bytes.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut partial_arr = [0u8; 32];
    partial_arr.copy_from_slice(&user_partial_bytes);
    let user_partial =
        PartialSignature::from_byte_array(&partial_arr).map_err(|_| StatusCode::BAD_REQUEST)?;

    let mut payout_state = session.payout_nonce_state.take().ok_or_else(|| {
        error!("❌ Payout nonce state not found");
        StatusCode::BAD_REQUEST
    })?;

    let user_pub_nonce = payout_state
        .user_pub_nonce
        .take()
        .ok_or(StatusCode::BAD_REQUEST)?;
    let solver_pub_nonce = payout_state
        .solver_pub_nonce
        .take()
        .ok_or(StatusCode::BAD_REQUEST)?;
    let sighash = payout_state.sighash.take().ok_or(StatusCode::BAD_REQUEST)?;
    let solver_sec_nonce = payout_state
        .solver_sec_nonce
        .take()
        .ok_or(StatusCode::BAD_REQUEST)?;
    let psbt_hex = payout_state.psbt_hex.take().ok_or(StatusCode::BAD_REQUEST)?;

    let solver_kp = session.solver_kp.clone();

    let mut key_agg_cache = session.key_agg_cache_untweaked.clone();
    if let Some(ref merkle_bytes) = session.merkle_root {
        apply_taproot_tweak(&mut key_agg_cache, merkle_bytes)?;
    }

    info!("   All session data retrieved successfully");

    let agg_nonce = AggregatedNonce::new(&[&user_pub_nonce, &solver_pub_nonce]);
    let musig_session = Session::new(&key_agg_cache, agg_nonce, &sighash);
    let solver_partial = musig_session.partial_sign(solver_sec_nonce, &solver_kp, &key_agg_cache);

    info!("   Generated solver partial signature");

    let agg_sig = musig_session.partial_sig_agg(&[&user_partial, &solver_partial]);
    let final_sig = agg_sig.verify(&key_agg_cache.agg_pk(), &sighash).map_err(|e| {
        error!("Signature verification failed: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let sig_bytes: [u8; 64] = *final_sig.as_ref();

    info!("✅ [PAYOUT] Final signature created and verified");

    let tx_bytes = hex::decode(&psbt_hex).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut tx: bitcoin::Transaction =
        bitcoin::consensus::deserialize(&tx_bytes).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    tx.input[0].witness = bitcoin::Witness::from_slice(&[&sig_bytes]);

    let signed_tx_hex = hex::encode(bitcoin::consensus::serialize(&tx));

    session.signed_payout_tx = Some(signed_tx_hex.clone());

    info!("   Stored signed payout tx ({} bytes)", signed_tx_hex.len() / 2);

    Ok(Json(SignResponse {
        final_sig: hex::encode(sig_bytes),
        signed_tx_hex,
    }))
}

async fn build_burn_tx(
    State(_state): State<SolverState>,
    Json(req): Json<BuildBurnRequest>,
) -> Result<Json<BuildBurnResponse>, StatusCode> {
    use bitcoin::{Amount, OutPoint, Txid};
    use bitcoin::consensus::serialize;

    info!("📥 Build burn transaction request:");
    info!("   Session: {}", req.session_id);
    info!("   Funding: {}:{}", req.funding_txid, req.funding_vout);
    info!("   Burn amount: {} sats", req.burn_amount_sats);

    let txid: Txid = req
        .funding_txid
        .parse()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let outpoint = OutPoint {
        txid,
        vout: req.funding_vout,
    };

    let funding_value = Amount::from_sat(req.funding_value_sats);
    let burn_amount = Amount::from_sat(req.burn_amount_sats);

    let intent_hash_bytes = hex::decode(
        &_state
            .sessions
            .lock()
            .unwrap()
            .get(&req.session_id)
            .ok_or(StatusCode::NOT_FOUND)?
            .intent_hash,
    )
    .map_err(|_| StatusCode::BAD_REQUEST)?;

    let mut payload = Vec::with_capacity(4 + 4 + 20);
    payload.extend_from_slice(b"BTI1");
    payload.extend_from_slice(&req.chain_id.to_be_bytes());
    payload.extend_from_slice(&intent_hash_bytes);

    let psbt = musig_utils::build_burn_psbt(
        outpoint,
        funding_value,
        burn_amount,
        &payload,
        bitcoin::Network::Regtest,
    )
    .map_err(|e| {
        error!("Error building burn PSBT: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let prevout = bitcoin::TxOut {
        value: funding_value,
        script_pubkey: bitcoin::ScriptBuf::new(),
    };

    let sighash = musig_utils::keyspend_sighash(
        &psbt,
        &prevout,
        bitcoin::sighash::TapSighashType::AllPlusAnyoneCanPay,
    )
    .map_err(|e| {
        error!("Error computing sighash: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let psbt_hex = hex::encode(serialize(
        &psbt
            .extract_tx()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    ));

    info!("✅ Burn PSBT built");
    info!("   Sighash: {}", hex::encode(sighash));

    Ok(Json(BuildBurnResponse {
        psbt_hex,
        sighash_hex: hex::encode(sighash),
    }))
}

async fn build_payout_tx(
    State(_state): State<SolverState>,
    Json(req): Json<BuildPayoutRequest>,
) -> Result<Json<BuildPayoutResponse>, StatusCode> {
    use bitcoin::{Address, Amount, OutPoint, Txid};
    use bitcoin::consensus::serialize;
    use std::str::FromStr;

    info!("📥 Build payout transaction request:");
    info!("   Session: {}", req.session_id);
    info!("   Funding: {}:{}", req.funding_txid, req.funding_vout);
    info!("   Payout to: {}", req.payout_address);
    info!("   Amount: {} sats", req.payout_amount_sats);

    let txid: Txid = req
        .funding_txid
        .parse()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let outpoint = OutPoint {
        txid,
        vout: req.funding_vout,
    };

    let funding_value = Amount::from_sat(req.funding_value_sats);
    let payout_amount = Amount::from_sat(req.payout_amount_sats);

    let payout_address = Address::from_str(&req.payout_address)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .assume_checked();

    let psbt = musig_utils::build_payout_psbt(
        outpoint,
        funding_value,
        payout_address.script_pubkey(),
        payout_amount,
    )
    .map_err(|e| {
        error!("Error building payout PSBT: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let prevout = bitcoin::TxOut {
        value: funding_value,
        script_pubkey: bitcoin::ScriptBuf::new(),
    };

    let sighash =
        musig_utils::keyspend_sighash(&psbt, &prevout, bitcoin::sighash::TapSighashType::Default)
            .map_err(|e| {
                error!("Error computing sighash: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

    let psbt_hex = hex::encode(serialize(
        &psbt
            .extract_tx()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    ));

    info!("✅ Payout PSBT built");
    info!("   Sighash: {}", hex::encode(sighash));

    Ok(Json(BuildPayoutResponse {
        psbt_hex,
        sighash_hex: hex::encode(sighash),
    }))
}

// ============================================================================
// Auto-Collaboration Logic
// ============================================================================

/// Check if a Bitcoin address has sufficient balance
async fn check_bitcoin_balance(address: &str, expected_sats: u64) -> Result<bool, String> {
    // TODO: Implement actual Bitcoin RPC check
    // For now, we'll trust that the escrow is funded if we got this far
    info!("   Checking balance for address {}: expecting {} sats", address, expected_sats);
    Ok(true)
}

/// Send laneBTC to user via Core Lane RPC
async fn send_lanebtc_to_user(
    state: &SolverState,
    session_id: &str,
    escrow_address: &str,
    user_address: &str,
    btc_amount: f64,
) -> Result<(), String> {
    info!("💸 Sending laneBTC to user...");
    info!("   Session: {}", session_id);
    info!("   Escrow: {}", escrow_address);
    info!("   User: {}", user_address);
    info!("   Amount: {} BTC", btc_amount);

    // Step 1: Check that escrow address has funds
    let amount_sats = (btc_amount * 100_000_000.0) as u64;
    if !check_bitcoin_balance(escrow_address, amount_sats).await? {
        return Err("Escrow address does not have sufficient funds".to_string());
    }

    info!("   ✅ Escrow address has funds");

    // Step 2: Send laneBTC to user via Core Lane RPC
    // Convert sats to wei (1 sat = 10^10 wei)
    let amount_wei = U256::from(amount_sats) * U256::from(10_000_000_000u64);
    
    // Parse user address
    let to_address = AlloyAddress::from_str(user_address)
        .map_err(|e| format!("Invalid user address: {}", e))?;

    info!("   Sending {} wei ({} sats) to {}", amount_wei, amount_sats, user_address);

    // Send laneBTC to user via Core Lane
    if let Some(signer) = &state.intent_system.signer {
        use alloy_provider::{Provider, ProviderBuilder};
        use alloy_network::EthereumWallet;
        use alloy_consensus::TxLegacy;
        use alloy_network::TxSigner;

        let url: url::Url = state.intent_system.provider_url.parse()
            .map_err(|e| format!("Invalid Core Lane URL: {}", e))?;
        
        let wallet = EthereumWallet::from(signer.clone());
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .on_http(url);

        // Get nonce
        let from_address = signer.address();
        let nonce = provider.get_transaction_count(from_address)
            .await
            .map_err(|e| format!("Failed to get nonce: {}", e))?;

        // Create legacy transaction
        let mut tx = TxLegacy {
            chain_id: Some(1281453634), // Core Lane chain ID
            nonce,
            gas_price: 1000000000, // 1 gwei
            gas_limit: 21000,
            to: alloy_primitives::TxKind::Call(to_address),
            value: amount_wei,
            input: alloy_primitives::Bytes::new(),
        };

        info!("   📡 Sending transaction to Core Lane...");
        
        // Sign and send
        use alloy_consensus::SignableTransaction;
        let signature = signer.sign_transaction(&mut tx).await
            .map_err(|e| format!("Failed to sign: {}", e))?;
        
        let signed_tx = tx.into_signed(signature);
        let tx_hash = signed_tx.hash();
        
        info!("   ✅ Transaction signed: 0x{:x}", tx_hash);
        info!("   📡 [TODO] Broadcast to Core Lane (provider.send_raw_transaction)");
        
        // Mark as sent in session
        let mut sessions = state.sessions.lock().unwrap();
        if let Some(session) = sessions.get_mut(session_id) {
            session.lanebtc_sent = true;
        }
        
        Ok(())
    } else {
        warn!("   ⚠️  No signer configured, cannot send laneBTC");
        warn!("   ⚠️  Solver is running in read-only mode");
        Ok(())
    }
}

async fn submit_intent(
    State(state): State<SolverState>,
    Json(payload): Json<IntentSubmissionRequest>,
) -> impl IntoResponse {
    info!(
        "📥 Received intent submission request from {}",
        payload.from
    );

    let eip712sig = match decode_hex_field(&payload.eip712sig) {
        Ok(sig) => {
            if sig.len() != 65 {
                return bad_request(format!(
                    "Invalid signature length: expected 65 bytes, got {}",
                    sig.len()
                ))
                .into_response();
            }
            sig
        }
        Err(err) => return err.into_response(),
    };

    let lock_data_bytes = match decode_hex_field(&payload.lock_data) {
        Ok(d) => d,
        Err(err) => return err.into_response(),
    };
    let intent_bytes = match decode_hex_field(&payload.intent_hex) {
        Ok(d) => d,
        Err(err) => return err.into_response(),
    };

    let lock_data: LockData = match parse_cbor_field(&lock_data_bytes) {
        Ok(d) => d,
        Err(err) => return err.into_response(),
    };
    let intent_data: IntentData = match parse_cbor_field(&intent_bytes) {
        Ok(d) => d,
        Err(err) => return err.into_response(),
    };

    let nonce = lock_data.nonce;
    let value = lock_data.value;

    let domain = Eip712Domain::from(&payload.typed_data.domain);
    let signer_address =
        match verify_eip712_signature(&domain, &intent_bytes, nonce, value, &eip712sig) {
            Ok(addr) => addr,
            Err(e) => {
                error!("EIP-712 signature verification failed: {}", e);
                return bad_request(format!("Invalid signature: {}", e)).into_response();
            }
        };

    let from_address = match Address::from_str(&payload.from) {
        Ok(addr) => addr,
        Err(e) => return bad_request(format!("Invalid from address: {}", e)).into_response(),
    };

    info!(
        "EIP-712 signature verified. Signer: {}, From: {}, Intent type: {:?}",
        signer_address, from_address, intent_data.intent_type
    );

    let nonce_u64 = nonce.to::<u64>();
    let intent_id =
        calculate_intent_id(signer_address, nonce_u64, Bytes::from(intent_bytes.clone()));

    if let Err(e) = state
        .intent_system
        .create_intent_and_lock(&eip712sig, &lock_data_bytes, signer_address)
        .await
    {
        error!("Failed to create intent: {}", e);
        return internal_error(format!("Failed to create intent: {}", e)).into_response();
    }

    info!("Successfully created intent with ID: 0x{:x}", intent_id);

    Json(IntentSubmissionResponse {
        success: true,
        intent_id: Some(format!("0x{:x}", intent_id)),
        message: "Intent created successfully".to_string(),
    })
    .into_response()
}

fn decode_hex_field(value: &str) -> Result<Vec<u8>, HttpError> {
    let trimmed = value.trim_start_matches("0x");
    hex::decode(trimmed).map_err(|e| bad_request(format!("Invalid hex: {}", e)))
}

fn parse_cbor_field<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, HttpError> {
    from_reader(Cursor::new(bytes)).map_err(|e| {
        error!("Failed to parse CBOR: {}", e);
        bad_request(format!("Invalid CBOR: {}", e))
    })
}

fn bad_request(message: impl Into<String>) -> HttpError {
    (
        StatusCode::BAD_REQUEST,
        Json(IntentSubmissionResponse {
            success: false,
            intent_id: None,
            message: message.into(),
        }),
    )
}

fn internal_error(message: impl Into<String>) -> HttpError {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(IntentSubmissionResponse {
            success: false,
            intent_id: None,
            message: message.into(),
        }),
    )
}
type HttpError = (StatusCode, Json<IntentSubmissionResponse>);

/// Response payload
#[derive(Debug, Serialize)]
pub struct IntentSubmissionResponse {
    pub success: bool,
    pub intent_id: Option<String>,
    pub message: String,
}

/// Request payload from the exit-intent-signer
#[derive(Debug, Deserialize)]
pub struct IntentSubmissionRequest {
    pub eip712sig: String,
    pub lock_data: String,
    pub typed_data: TypedData,
    pub intent_hex: String,
    pub from: String,
    pub chain_id: u64,
    pub verifying_contract: String,
}

/// Typed data structure from the request
#[derive(Debug, Deserialize)]
pub struct TypedData {
    pub domain: serde_json::Value,
    pub types: serde_json::Value,
    pub message: CreateIntentMessage,
}

/// EIP-712 message structure
#[derive(Debug, Deserialize)]
pub struct CreateIntentMessage {
    pub intent: String,
    pub nonce: String,
    pub value: String,
}
// ============================================================================
// Public API
// ============================================================================

pub fn create_router(state: SolverState) -> Router {
    Router::new()
        .route("/", get(health_check))
        .route("/api/quote", post(get_quote))
        .route("/api/escrow/init", post(init_escrow))
        .route("/api/burn/build", post(build_burn_tx))
        .route("/api/burn/nonce", post(exchange_burn_nonce))
        .route("/api/burn/sign", post(partial_sign_burn))
        .route("/api/payout/build", post(build_payout_tx))
        .route("/api/payout/nonce", post(exchange_payout_nonce))
        .route("/api/payout/sign", post(partial_sign_payout))
        .route("/intents", post(submit_intent))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

pub async fn serve(port: u16, intent_system: Arc<CoreLaneIntentSystem>) -> anyhow::Result<()> {
    let mut state = SolverState::new(intent_system);
    
    let app = create_router(state);

    let addr = format!("127.0.0.1:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    info!("✅ Solver HTTP API listening on http://{}", addr);

    axum::serve(listener, app).await?;

    Ok(())
}

