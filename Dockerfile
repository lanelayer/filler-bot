FROM rust:1.86

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libudev-dev \
    build-essential \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

RUN cargo build --release

EXPOSE 8080

ENV CORE_LANE_URL=http://127.0.0.1:8545
ENV BITCOIN_RPC_URL=http://127.0.0.1:18443
ENV FILLER_ADDRESS=0x1234567890123456789012345678901234567890
ENV EXIT_MARKETPLACE=0x0000000000000000000000000000000000000045

CMD ["./target/release/lanelayer-filler-bot", "start"]
