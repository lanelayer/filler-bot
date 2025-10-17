use anyhow::Result;
use clap::{Parser, Subcommand};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, error};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use lanelayer_filler_bot::{
    CoreLaneClient,
    BitcoinClient,
    IntentManager,
    FillerBot,
    SimulatorTester,
};

#[derive(Parser)]
#[command(name = "lanelayer-filler-bot")]
#[command(about = "LaneLayer Filler Bot - Fulfills user intents by exchanging laneBTC for BTC")]
struct Cli {
    /// Disable colored output
    #[arg(long)]
    plain: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the filler bot
    Start {
        /// Core Lane JSON-RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        core_lane_url: String,

        /// Bitcoin backend type (electrum or rpc)
        #[arg(long, default_value = "electrum")]
        bitcoin_backend: String,

        /// Electrum server URL (used when bitcoin-backend=electrum)
        #[arg(long, default_value = "tcp://127.0.0.1:50001")]
        electrum_url: String,

        /// Bitcoin RPC URL (used when bitcoin-backend=rpc)
        #[arg(long, default_value = "http://127.0.0.1:18443")]
        bitcoin_rpc_url: String,

        /// Bitcoin RPC username (used when bitcoin-backend=rpc)
        #[arg(long, default_value = "bitcoin")]
        bitcoin_rpc_user: String,

        /// Bitcoin RPC password (used when bitcoin-backend=rpc)
        #[arg(long)]
        bitcoin_rpc_password: Option<String>,

        /// Bitcoin mnemonic phrase (BIP39)
        #[arg(long)]
        bitcoin_mnemonic: Option<String>,

        /// Path to file containing Bitcoin mnemonic
        #[arg(long)]
        mnemonic_file: Option<String>,

        /// Bitcoin network (bitcoin, testnet, signet, regtest)
        #[arg(long, default_value = "regtest")]
        bitcoin_network: String,

        /// Bitcoin wallet name (used for database filename)
        #[arg(long, default_value = "filler-bot")]
        bitcoin_wallet: String,

        /// Exit marketplace address
        #[arg(long, default_value = "0x0000000000000000000000000000000000000045")]
        exit_marketplace: String,

        /// Filler bot address (our Core Lane address)
        #[arg(long)]
        filler_address: String,

        /// Polling interval in seconds
        #[arg(long, default_value = "10")]
        poll_interval: u64,
    },

    /// Check Core Lane connection
    TestCoreLane {
        /// Core Lane JSON-RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        core_lane_url: String,
    },

    /// Check Bitcoin connection
    TestBitcoin {
        /// Bitcoin backend type (electrum or rpc)
        #[arg(long, default_value = "electrum")]
        bitcoin_backend: String,

        /// Electrum server URL (used when bitcoin-backend=electrum)
        #[arg(long, default_value = "tcp://127.0.0.1:50001")]
        electrum_url: String,

        /// Bitcoin RPC URL (used when bitcoin-backend=rpc)
        #[arg(long, default_value = "http://127.0.0.1:18443")]
        bitcoin_rpc_url: String,

        /// Bitcoin RPC username (used when bitcoin-backend=rpc)
        #[arg(long, default_value = "bitcoin")]
        bitcoin_rpc_user: String,

        /// Bitcoin RPC password (used when bitcoin-backend=rpc)
        #[arg(long)]
        bitcoin_rpc_password: Option<String>,

        /// Bitcoin mnemonic phrase
        #[arg(long)]
        bitcoin_mnemonic: Option<String>,

        /// Path to file containing mnemonic
        #[arg(long)]
        mnemonic_file: Option<String>,

        /// Bitcoin network
        #[arg(long, default_value = "regtest")]
        bitcoin_network: String,

        /// Bitcoin wallet name
        #[arg(long, default_value = "test-wallet")]
        bitcoin_wallet: String,
    },

    /// Test against IntentSystem simulator contract
    TestSimulator {
        /// Core Lane JSON-RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        core_lane_url: String,

        /// Simulator contract address
        #[arg(long)]
        simulator_address: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "lanelayer_filler_bot=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting LaneLayer Filler Bot");

    let cli = Cli::parse();

    match &cli.command {
        Commands::Start {
            core_lane_url,
            bitcoin_backend,
            electrum_url,
            bitcoin_rpc_url,
            bitcoin_rpc_user,
            bitcoin_rpc_password,
            bitcoin_mnemonic,
            mnemonic_file,
            bitcoin_network,
            bitcoin_wallet,
            exit_marketplace,
            filler_address,
            poll_interval,
        } => {
            // Resolve mnemonic from various sources
            let mnemonic_str = resolve_mnemonic(
                bitcoin_mnemonic.as_deref(),
                mnemonic_file.as_deref(),
            )?;

            if !cli.plain {
                info!("🚀 Starting Filler Bot with BDK...");
            }

            // Parse the exit marketplace address
            let exit_marketplace_addr = exit_marketplace.parse()
                .map_err(|e| anyhow::anyhow!("Invalid exit marketplace address: {}", e))?;

            // Parse the filler address
            let filler_addr = filler_address.parse()
                .map_err(|e| anyhow::anyhow!("Invalid filler address: {}", e))?;

            let core_lane_client = Arc::new(CoreLaneClient::new(core_lane_url.clone()));
            
            // Create Bitcoin client with specified backend
            let bitcoin_client = Arc::new(Mutex::new(match bitcoin_backend.as_str() {
                "electrum" => {
                    BitcoinClient::new_electrum(
                        electrum_url.clone(),
                        mnemonic_str,
                        bitcoin_network.clone(),
                        bitcoin_wallet.clone(),
                    ).await?
                }
                "rpc" => {
                    let rpc_password = bitcoin_rpc_password.as_deref()
                        .ok_or_else(|| anyhow::anyhow!("Bitcoin RPC password required when using RPC backend. Set BITCOIN_RPC_PASSWORD environment variable or use --bitcoin-rpc-password"))?;
                    
                    BitcoinClient::new_rpc(
                        bitcoin_rpc_url.clone(),
                        bitcoin_rpc_user.clone(),
                        rpc_password.to_string(),
                        mnemonic_str,
                        bitcoin_network.clone(),
                        bitcoin_wallet.clone(),
                    ).await?
                }
                _ => return Err(anyhow::anyhow!("Invalid bitcoin backend: {}. Must be 'electrum' or 'rpc'", bitcoin_backend)),
            }));

            // Create intent manager
            let intent_manager = Arc::new(Mutex::new(IntentManager::new()));

            // Create and start the filler bot
            let bot = FillerBot::new(
                core_lane_client,
                bitcoin_client,
                intent_manager,
                exit_marketplace_addr,
                filler_addr,
                *poll_interval,
            );

            bot.start().await?;
        }

        Commands::TestCoreLane { core_lane_url } => {
            let client = CoreLaneClient::new(core_lane_url.clone());
            match client.test_connection().await {
                Ok(block_number) => {
                    info!("✅ Core Lane connection successful! Latest block: {}", block_number);
                }
                Err(e) => {
                    error!("❌ Core Lane connection failed: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::TestBitcoin {
            bitcoin_backend,
            electrum_url,
            bitcoin_rpc_url,
            bitcoin_rpc_user,
            bitcoin_rpc_password,
            bitcoin_mnemonic,
            mnemonic_file,
            bitcoin_network,
            bitcoin_wallet,
        } => {
            // Resolve mnemonic
            let mnemonic_str = resolve_mnemonic(
                bitcoin_mnemonic.as_deref(),
                mnemonic_file.as_deref(),
            )?;

            info!("🔧 Testing Bitcoin connection via {} (BDK)...", bitcoin_backend);

            let client = match bitcoin_backend.as_str() {
                "electrum" => {
                    BitcoinClient::new_electrum(
                        electrum_url.clone(),
                        mnemonic_str,
                        bitcoin_network.clone(),
                        bitcoin_wallet.clone(),
                    ).await?
                }
                "rpc" => {
                    let rpc_password = bitcoin_rpc_password.as_deref()
                        .ok_or_else(|| anyhow::anyhow!("Bitcoin RPC password required when using RPC backend. Set BITCOIN_RPC_PASSWORD environment variable or use --bitcoin-rpc-password"))?;
                    
                    BitcoinClient::new_rpc(
                        bitcoin_rpc_url.clone(),
                        bitcoin_rpc_user.clone(),
                        rpc_password.to_string(),
                        mnemonic_str,
                        bitcoin_network.clone(),
                        bitcoin_wallet.clone(),
                    ).await?
                }
                _ => return Err(anyhow::anyhow!("Invalid bitcoin backend: {}. Must be 'electrum' or 'rpc'", bitcoin_backend)),
            };

            match client.test_connection().await {
                Ok(block_count) => {
                    info!("✅ Bitcoin connection successful! Block count: {}", block_count);
                    
                    // Show wallet info
                    let mut client_mut = client;
                    let balance = client_mut.refresh_balance().await?;
                    info!("💰 Wallet balance: {} sats", balance);
                }
                Err(e) => {
                    error!("❌ Bitcoin connection failed: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::TestSimulator {
            core_lane_url,
            simulator_address,
        } => {
            // Parse the simulator address
            let simulator_addr = simulator_address.parse()
                .map_err(|e| anyhow::anyhow!("Invalid simulator address: {}", e))?;

            // Create simulator tester
            let tester = SimulatorTester::new(core_lane_url.clone(), simulator_addr);

            // Run all tests
            match tester.run_all_tests().await {
                Ok(_) => {
                    info!("🎉 All simulator tests completed successfully!");
                }
                Err(e) => {
                    error!("❌ Simulator tests failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }

    Ok(())
}

/// Resolve mnemonic from various sources (argument, file, or environment variable)
fn resolve_mnemonic(mnemonic: Option<&str>, mnemonic_file: Option<&str>) -> Result<String> {
    // First priority: command line argument
    if let Some(mnemonic_str) = mnemonic {
        if !mnemonic_str.is_empty() {
            return Ok(mnemonic_str.to_string());
        }
    }

    // Second priority: file
    if let Some(file_path) = mnemonic_file {
        let content = std::fs::read_to_string(file_path)
            .map_err(|e| anyhow::anyhow!("Failed to read mnemonic file {}: {}", file_path, e))?;
        let trimmed = content.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }

    // Third priority: environment variable (already handled by clap with env = "BITCOIN_MNEMONIC")
    Err(anyhow::anyhow!(
        "No mnemonic provided. Use --bitcoin-mnemonic, --mnemonic-file, or BITCOIN_MNEMONIC environment variable"
    ))
}