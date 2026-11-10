# Reproducible build image for barking-cli, barking-node and barking-push (static musl binaries).
# Base pinned by digest (multi-architecture index, rust 1.99.1, Alpine 3.24).
FROM rust:1.99.1-alpine3.24@sha256:44819b27be4c97b0e4d7203bd2e02c4820f97700211b6a37fb4c246a2de59383

# The complete installed APK closure is pinned: a missing version fails the build.
COPY apk/install.sh apk/build.txt /etc/barking-apk/
RUN sh /etc/barking-apk/install.sh /etc/barking-apk/build.txt

# The image's compiler (1.99.1) is authoritative: rust-toolchain.toml is neutralized.
ENV RUSTUP_TOOLCHAIN=1.99.1
