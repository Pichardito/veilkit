# Builds the `veilkit` CLI into a minimal image.
#   podman build -t veilkit .
#   echo "ssn 219-09-9999" | podman run -i veilkit redact --packs pii
FROM rust:1.97-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY packs ./packs
RUN cargo build --release -p veilkit-cli

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/veilkit /usr/local/bin/veilkit
ENTRYPOINT ["/usr/local/bin/veilkit"]
CMD ["--help"]
