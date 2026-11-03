# Runtime image of barking-node: the static musl binary of a release, alone
# on an empty base (no shell, no libc, no package). The build context is a
# release directory (binaries and SHA256SUMS, see scripts/repro-build.sh):
#   docker build -f docker/node.Dockerfile --build-arg VERSION=0.1.0 -t barking-node dist
# The binary of the target architecture is checked against SHA256SUMS.

# Preparation only (checksum, tree, ownership); nothing of it is kept.
# Base pinned by digest (multi-architecture index, Alpine 3.24.3).
FROM alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a AS prepare
ARG VERSION
ARG TARGETARCH
COPY . /release/
RUN set -eu; \
    [ -n "$VERSION" ] || { echo "error: --build-arg VERSION is required" >&2; exit 1; }; \
    case "$TARGETARCH" in \
      amd64) arch=x86_64 ;; \
      arm64) arch=aarch64 ;; \
      *) echo "error: unsupported architecture $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    name="barking-node-$VERSION-$arch-unknown-linux-musl"; \
    cd /release; \
    grep "  $name\$" SHA256SUMS | sha256sum -c -; \
    mkdir -p /out/var/lib/barking-node /out/tmp; \
    install -m 0755 "$name" /out/barking-node; \
    chown 65532:65532 /out/var/lib/barking-node; \
    chmod 0700 /out/var/lib/barking-node; \
    chmod 1777 /out/tmp

FROM scratch
COPY --from=prepare /out/ /
# Unprivileged numeric user (no /etc/passwd); UDP port > 1024.
USER 65532:65532
# node.key and node.db. A named volume takes the ownership and mode 0700 of
# this directory at its creation.
VOLUME /var/lib/barking-node
EXPOSE 4433/udp
ENTRYPOINT ["/barking-node"]
# Specification defaults; with a configuration:
# run --config /etc/barking-node.toml (mounted read-only).
CMD ["run"]
