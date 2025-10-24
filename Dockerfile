FROM rust:1.86 AS builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libudev-dev \
    build-essential \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY src ./src
COPY Cargo.toml ./Cargo.toml
COPY Cargo.lock ./Cargo.lock
RUN cargo build --release

FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y \
    libssl3 \
    libudev1 \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/lanelayer-filler-bot .
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8080

# Set default environment variables (can be overridden at runtime)
ENV CORE_LANE_URL=http://core-lane:8545
ENV BITCOIN_BACKEND=electrum
ENV ELECTRUM_URL=ssl://electrum.blockstream.info:50002
ENV BITCOIN_RPC_URL=https://bitcoin-rpc.publicnode.com
ENV BITCOIN_RPC_USER=bitcoin
ENV BITCOIN_RPC_PASSWORD=
ENV BITCOIN_NETWORK=mainnet
ENV BITCOIN_WALLET=filler-bot
ENV EXIT_MARKETPLACE=0x0000000000000000000000000000000000000045
ENV POLL_INTERVAL=10
ENV BITCOIN_MNEMONIC=
ENV MNEMONIC_FILE=

ENTRYPOINT ["/entrypoint.sh"]
