# Reproducible build image for barking-cli.
# Base pinned by digest (multi-architecture index, rust 1.94.1, Debian bookworm).
FROM rust:1.94.1-slim-bookworm@sha256:cf9dd0ec73e75f827fe59123fff9dc65af1a1c8363c3c31ee8d7f8ad0b6a5fb2

# Packages come from a dated Debian snapshot: same versions on every build.
ARG DEBIAN_SNAPSHOT=20261001T000000Z
RUN rm -f /etc/apt/sources.list /etc/apt/sources.list.d/* \
 && printf '%s\n' \
      "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}/ bookworm main" \
      "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}/ bookworm-security main" \
      > /etc/apt/sources.list \
 && printf 'Acquire::Check-Valid-Until "false";\nAcquire::Retries "5";\n' > /etc/apt/apt.conf.d/99snapshot \
 && apt-get update \
 && apt-get install -y --no-install-recommends musl-tools make perl \
 && rm -rf /var/lib/apt/lists/*

# The image's compiler (1.94.1) is authoritative: rust-toolchain.toml is neutralized.
ENV RUSTUP_TOOLCHAIN=1.94.1
RUN rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
