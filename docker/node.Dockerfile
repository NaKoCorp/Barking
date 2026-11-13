# Runtime image of barking-node: the static musl binary of a release, alone
# on an empty base (no shell, no libc, no package). The build context is a
# release directory (binaries and SHA256SUMS, see scripts/repro-build.sh):
#   docker build -f docker/node.Dockerfile --build-arg VERSION=0.1.0 -t barking-node dist
# The binary of the target architecture is checked against SHA256SUMS. For
# several architectures at once (no emulation needed), the release directory
# holds the binary of each of them:
#   docker buildx build --platform linux/amd64,linux/arm64 -f docker/node.Dockerfile \
#     --build-arg VERSION=0.1.0 dist

# Preparation only (checksum, tree, ownership); nothing of it is kept. It runs
# on the build platform, whatever the target: it only copies the binary of
# TARGETARCH and never executes it. Base pinned by digest (multi-architecture
# index, Alpine 3.24.4).
FROM --platform=$BUILDPLATFORM alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS prepare
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
