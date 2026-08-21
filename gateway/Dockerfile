FROM rust:1.97.1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --locked --release -p hand-egress-gateway

FROM debian:bookworm-slim
RUN groupadd --system --gid 65532 gateway \
    && useradd --system --uid 65532 --gid 65532 --no-create-home --home-dir /nonexistent gateway
COPY --from=build /src/target/release/hand-egress-gateway /usr/local/bin/hand-egress-gateway
USER 65532:65532
EXPOSE 8080 8081
ENTRYPOINT ["/usr/local/bin/hand-egress-gateway"]
