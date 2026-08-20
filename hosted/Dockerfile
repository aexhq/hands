FROM rust:1.97.1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --locked --release -p hand-brain-aws --bin brain-hand-aws

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/brain-hand-aws /usr/local/bin/brain-hand-aws
EXPOSE 8700
ENTRYPOINT ["/usr/local/bin/brain-hand-aws"]
