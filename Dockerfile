FROM rust:1.81.0 as builder
RUN apt-get update && apt-get install -y clang

WORKDIR /waterfalls
COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo build --release

FROM debian:stable-slim
RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /waterfalls/target/release/waterfalls /usr/local/bin/waterfalls
ENTRYPOINT [ "waterfalls" ]