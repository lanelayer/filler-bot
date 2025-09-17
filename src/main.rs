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
    IntentContract,
    FillerBot,
    SimulatorTester,
};

#[derive(Parser)]
#[command(name = "lanelayer-filler-bot")]
#[command(about = "LaneLayer Filler Bot - Fulfills user intents by exchanging laneBTC for BTC")]
struct Cli {
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

        /// Bitcoin RPC URL
        #[arg(long, default_value = "http://127.0.0.1:18443")]
        bitcoin_rpc_url: String,

        /// Bitcoin RPC username
        #[arg(long, default_value = "bitcoin")]
        bitcoin_rpc_user: String,

        /// Bitcoin RPC password
        #[arg(long)]
        bitcoin_rpc_password: String,

        /// Bitcoin wallet name
        #[arg(long, default_value = "filler-bot")]
        bitcoin_wallet: String,

        /// Exit marketplace address (0x0000000000000000000000000000000000ExitMkT)
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
        /// Bitcoin RPC URL
        #[arg(long, default_value = "http://127.0.0.1:18443")]
        bitcoin_rpc_url: String,

        /// Bitcoin RPC username
        #[arg(long, default_value = "bitcoin")]
        bitcoin_rpc_user: String,

        /// Bitcoin RPC password
        #[arg(long)]
        bitcoin_rpc_password: String,
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
            bitcoin_rpc_url,
            bitcoin_rpc_user,
            bitcoin_rpc_password,
            bitcoin_wallet,
            exit_marketplace,
            filler_address,
            poll_interval,
        } => {
            // Parse the exit marketplace address
            let exit_marketplace_addr = exit_marketplace.parse()
                .map_err(|e| anyhow::anyhow!("Invalid exit marketplace address: {}", e))?;

            // Parse the filler address
            let filler_addr = filler_address.parse()
                .map_err(|e| anyhow::anyhow!("Invalid filler address: {}", e))?;

            // Create clients
            let core_lane_client = Arc::new(CoreLaneClient::new(core_lane_url.clone()));
            let bitcoin_client = Arc::new(BitcoinClient::new(
                bitcoin_rpc_url.clone(),
                bitcoin_rpc_user.clone(),
                bitcoin_rpc_password.clone(),
                bitcoin_wallet.clone(),
            )?);

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
            bitcoin_rpc_url,
            bitcoin_rpc_user,
            bitcoin_rpc_password
        } => {
            let client = BitcoinClient::new(
                bitcoin_rpc_url.clone(),
                bitcoin_rpc_user.clone(),
                bitcoin_rpc_password.clone(),
                "test".to_string(),
            )?;

            match client.test_connection().await {
                Ok(block_count) => {
                    info!("✅ Bitcoin connection successful! Block count: {}", block_count);
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