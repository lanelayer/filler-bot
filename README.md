# LaneLayer Filler Bot

A **filler bot** for LaneLayer that listens for user intents and fulfills them by exchanging laneBTC for BTC.

## Overview

The LaneLayer Filler Bot is an automated system that:

1. **Listens** for exit intents on Core Lane (users sending laneBTC to the exit marketplace)
2. **Fulfills** intents by sending BTC to users' requested Bitcoin addresses
3. **Receives** laneBTC tokens in return (plus fees)

### How It Works

Users who want to exchange laneBTC for BTC:
1. Send laneBTC to the **exit marketplace** (0x000...45) with their desired Bitcoin address
2. The filler bot detects this transaction and parses the intent
3. The filler bot sends real BTC to the user's requested address
4. The filler bot receives the user's laneBTC as payment

## How It Works

### User Intent Flow

1. **User Intent**: A user says *"I have laneBTC and I want BTC at address X on the L1"*
2. **Intent Detection**: The bot monitors Core Lane blocks for transactions to the intent contract (`0x00..45`)
3. **Intent Parsing**: The bot decodes the intent data using the Intent ABI
4. **Locking**: The bot attempts to lock the intent using `lockIntentForSolving(intentId)`
5. **Fulfillment**: The bot sends BTC to the user's requested Bitcoin address
6. **Confirmation**: Once BTC is confirmed, the bot calls `solveIntent(intentId, blockNumber)`

### Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   User Intent   │    │   Core Lane      │    │  Bitcoin L1     │
│                 │    │   (JSON-RPC)     │    │   (Signet RPC)  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         │ 1. Send intent        │                       │
         │──────────────────────▶│                       │
         │                       │                       │
         │                       │ 2. Bot detects        │
         │                       │◀──────────────────────│
         │                       │                       │
         │                       │ 3. Lock intent        │
         │                       │                       │
         │                       │ 4. Send BTC           │
         │                       │──────────────────────▶│
         │ 5. Receive BTC        │                       │
         │◀──────────────────────│                       │
         │                       │                       │
         │                       │ 6. Receive laneBTC    │
         │                       │◀──────────────────────│
         │                       │                       │
         │                       │ 7. Solve intent       │
         │                       │                       │
```

## Setup

### Prerequisites

- **Core Lane Node**: Running and accessible via JSON-RPC
- **Bitcoin Signet Node**: Running with RPC enabled
- **Rust Toolchain**: 1.70+

### Configuration

The bot requires two wallet setups:

1. **Bitcoin Signet Wallet**: Preloaded with BTC for fulfilling intents
2. **Core Lane Wallet**: For interacting with the intent contract

## Usage

### Build

```bash
cargo build --release
```

### Run

```bash
# Start the filler bot
./target/debug/lanelayer-filler-bot start \
  --core-lane-url "http://127.0.0.1:8546" \
  --core-lane-private-key "your_private_key_here" \
  --bitcoin-backend "rpc" \
  --bitcoin-rpc-url "http://127.0.0.1:18443" \
  --bitcoin-rpc-password "bitcoin123" \
  --exit-marketplace "0x0000000000000000000000000000000000000045" \
  --bitcoin-mnemonic "your_mnemonic_phrase_here" \
  --bitcoin-wallet "bot_wallet"
```

### Fund the Bot

```bash
# Fund the bot's float address with BTC (replace with actual address from bot logs)
docker exec -it bitcoin-regtest bitcoin-cli -regtest -rpcuser=bitcoin -rpcpassword=bitcoin123 generatetoaddress 101 "your_float_address_here"
```

### Test Connections

```bash
# Test Core Lane connection
./target/release/lanelayer-filler-bot test-core-lane \
  --core-lane-url "http://127.0.0.1:8545"

# Test Bitcoin connection
./target/release/lanelayer-filler-bot test-bitcoin \
  --bitcoin-rpc-url "http://127.0.0.1:18443" \
  --bitcoin-rpc-password "bitcoin123"
```

## Configuration Options

### Core Lane Options
- `--core-lane-url`: Core Lane JSON-RPC URL (default: http://127.0.0.1:8545)
- `--core-lane-private-key`: Private key for signing transactions (required)
- `--exit-marketplace`: Exit marketplace address (default: 0x0000000000000000000000000000000000000045)

### Bitcoin Options
- `--bitcoin-backend`: Backend type - `electrum` or `rpc` (default: electrum)
- `--electrum-url`: Electrum server URL (default: tcp://127.0.0.1:50001)
- `--bitcoin-rpc-url`: Bitcoin RPC URL (default: http://127.0.0.1:18443)
- `--bitcoin-rpc-user`: Bitcoin RPC username (default: bitcoin)
- `--bitcoin-rpc-password`: Bitcoin RPC password (required for RPC backend)
- `--bitcoin-mnemonic`: BIP39 mnemonic phrase for Bitcoin wallet (required)
- `--mnemonic-file`: Path to file containing mnemonic (alternative to --bitcoin-mnemonic)
- `--bitcoin-network`: Bitcoin network - `bitcoin`, `testnet`, `signet`, `regtest` (default: regtest)
- `--bitcoin-wallet`: Bitcoin wallet name (default: filler-bot)

### Other Options
- `--poll-interval`: Polling interval in seconds (default: 10)

## Intent Management

The bot maintains an internal database of intents with the following states:

- **Pending**: Intent detected but not yet locked
- **Locked**: We've locked the intent for solving
- **Fulfilling**: We're in the process of fulfilling (sent BTC)
- **Fulfilled**: BTC sent and confirmed, ready to solve
- **Solved**: Intent solved on Core Lane
- **Failed**: Something went wrong

## Monitoring

The bot provides detailed logging for monitoring:

- Intent detection and parsing
- Bitcoin transaction creation and confirmation
- Core Lane contract interactions
- Error handling and recovery

## Development Status

### ✅ Completed
- Basic repository setup with Rust
- Bitcoin wallet integration with BDK (Electrum + RPC backends)
- Core Lane JSON-RPC client with transaction signing
- Intent management system with state tracking
- Intent ABI parsing with CBOR support
- Transaction signing and submission for lock/solve operations
- Bitcoin transaction monitoring with confirmation tracking
- Filler bot logic with race condition handling

### 🚧 In Progress
- Advanced monitoring and metrics
- Production testing and hardening

### TODO
- Configuration file support
- Docker containerization
- Fee optimization strategies
- Multi-intent batching

## Contributing

This is an early implementation. The architecture and APIs may change significantly as development progresses.

## License
