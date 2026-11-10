# Fuzzing image for barking-core: dated nightly + pinned cargo-fuzz.
# Approved glibc exception: Rust AddressSanitizer does not support musl targets.
# Base pinned by digest (multi-architecture index, rust 1.99.1, Debian bookworm).
FROM rust:1.99.1-slim-bookworm@sha256:f2c004e3d2d8b547e8cf7ffbc29205385f4e71d23e53e4e383065db5e9f822cd

# Packages come from a dated Debian snapshot: same versions on every build.
# Match perl-base to the snapshot when the base image carries a newer version.
ARG DEBIAN_SNAPSHOT=20261001T000000Z
RUN rm -f /etc/apt/sources.list /etc/apt/sources.list.d/* \
 && printf '%s\n' \
      "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}/ bookworm main" \
      "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}/ bookworm-security main" \
      > /etc/apt/sources.list \
 && printf 'Acquire::Check-Valid-Until "false";\nAcquire::Retries "5";\n' > /etc/apt/apt.conf.d/99snapshot \
 && apt-get update \
 && apt-get install -y --no-install-recommends --allow-downgrades \
      g++ make perl perl-base=5.36.0-7+deb12u3 \
 && rm -rf /var/lib/apt/lists/*

# Dated nightly (libFuzzer requires -Zsanitizer); it is authoritative, rust-toolchain.toml is neutralized.
ARG NIGHTLY=nightly-2026-10-01
ENV RUSTUP_TOOLCHAIN=${NIGHTLY}
RUN rustup toolchain install "${NIGHTLY}" --profile minimal --component llvm-tools-preview \
 && cargo install --locked --version 0.13.2 cargo-fuzz
