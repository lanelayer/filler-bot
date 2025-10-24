#!/bin/bash
set -e

# Clean up any existing wallet database files
rm -f /app/*-wallet.db

# Default values
CORE_LANE_URL=${CORE_LANE_URL:-"http://core-lane:8545"}
BITCOIN_BACKEND=${BITCOIN_BACKEND:-"electrum"}
ELECTRUM_URL=${ELECTRUM_URL:-"ssl://electrum.blockstream.info:50002"}
BITCOIN_RPC_URL=${BITCOIN_RPC_URL:-"https://bitcoin-rpc.publicnode.com"}
BITCOIN_RPC_USER=${BITCOIN_RPC_USER:-"bitcoin"}
BITCOIN_RPC_PASSWORD=${BITCOIN_RPC_PASSWORD:-""}
BITCOIN_MNEMONIC=${BITCOIN_MNEMONIC:-""}
MNEMONIC_FILE=${MNEMONIC_FILE:-""}
BITCOIN_NETWORK=${BITCOIN_NETWORK:-"mainnet"}
BITCOIN_WALLET=${BITCOIN_WALLET:-"filler-bot"}
EXIT_MARKETPLACE=${EXIT_MARKETPLACE:-"0x0000000000000000000000000000000000000045"}
POLL_INTERVAL=${POLL_INTERVAL:-"10"}
FILLER_ADDRESS=${FILLER_ADDRESS:-""}

# Build command arguments
ARGS=("start")

# Add Core Lane arguments
ARGS+=("--core-lane-url" "$CORE_LANE_URL")

if [ -n "$CORE_LANE_PRIVATE_KEY" ]; then
    ARGS+=("--core-lane-private-key" "$CORE_LANE_PRIVATE_KEY")
fi

# Add Bitcoin arguments
ARGS+=("--bitcoin-backend" "$BITCOIN_BACKEND")

if [ "$BITCOIN_BACKEND" = "electrum" ]; then
    ARGS+=("--electrum-url" "$ELECTRUM_URL")
elif [ "$BITCOIN_BACKEND" = "rpc" ]; then
    ARGS+=("--bitcoin-rpc-url" "$BITCOIN_RPC_URL")
    ARGS+=("--bitcoin-rpc-user" "$BITCOIN_RPC_USER")
fi

# Add Bitcoin RPC password (required regardless of backend)
if [ -n "$BITCOIN_RPC_PASSWORD" ]; then
    ARGS+=("--bitcoin-rpc-password" "$BITCOIN_RPC_PASSWORD")
fi

# Add mnemonic (either from environment or file)
if [ -n "$BITCOIN_MNEMONIC" ]; then
    ARGS+=("--bitcoin-mnemonic" "$BITCOIN_MNEMONIC")
elif [ -n "$MNEMONIC_FILE" ]; then
    ARGS+=("--mnemonic-file" "$MNEMONIC_FILE")
else
    echo "Error: Either BITCOIN_MNEMONIC or MNEMONIC_FILE must be set" >&2
    exit 1
fi

# Add other Bitcoin arguments
ARGS+=("--bitcoin-network" "$BITCOIN_NETWORK")
ARGS+=("--bitcoin-wallet" "$BITCOIN_WALLET")

# Add exit marketplace
ARGS+=("--exit-marketplace" "$EXIT_MARKETPLACE")

# Add poll interval
ARGS+=("--poll-interval" "$POLL_INTERVAL")

# Note: filler-address is automatically derived from core-lane-private-key
# No need to pass it as an argument

# Execute the filler bot with all arguments
exec ./lanelayer-filler-bot "${ARGS[@]}"