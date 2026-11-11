# Runtime image of barking-push: the static musl binary of a release and a CA
# bundle (APNs TLS is verified against it), on an empty base (no shell, no
# libc, no package). The build context is a release directory (binaries and
# SHA256SUMS, see scripts/repro-build.sh); the pinned APK closure comes from
# the `apk` named context:
#   docker build -f docker/push.Dockerfile --build-context apk=docker/apk \
#     --build-arg VERSION=0.1.0 -t barking-push dist
# The binary of the target architecture is checked against SHA256SUMS.

# Preparation only (checksum, CA bundle, tree, ownership); nothing of it is
# kept but /out. Base pinned by digest (multi-architecture index, Alpine 3.24.4).
FROM alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS prepare
ARG VERSION
ARG TARGETARCH
COPY --from=apk install.sh push.txt /etc/barking-apk/
RUN sh /etc/barking-apk/install.sh /etc/barking-apk/push.txt
COPY . /release/
RUN set -eu; \
    [ -n "$VERSION" ] || { echo "error: --build-arg VERSION is required" >&2; exit 1; }; \
    case "$TARGETARCH" in \
      amd64) arch=x86_64 ;; \
      arm64) arch=aarch64 ;; \
      *) echo "error: unsupported architecture $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    name="barking-push-$VERSION-$arch-unknown-linux-musl"; \
    cd /release; \
    grep "  $name\$" SHA256SUMS | sha256sum -c -; \
    mkdir -p /out/var/lib/barking-push /out/tmp /out/etc/ssl/certs; \
    install -m 0755 "$name" /out/barking-push; \
    install -m 0644 /etc/ssl/certs/ca-certificates.crt /out/etc/ssl/certs/ca-certificates.crt; \
    chown 65532:65532 /out/var/lib/barking-push; \
    chmod 0700 /out/var/lib/barking-push; \
    chmod 1777 /out/tmp

FROM scratch
COPY --from=prepare /out/ /
# Unprivileged numeric user (no /etc/passwd); UDP port > 1024.
USER 65532:65532
# Relay secrets: node.key, seal keys and the APNs .p8 (mode 0600, owned by
# 65532). A named volume takes the ownership and mode 0700 of this directory
# at its creation.
VOLUME /var/lib/barking-push
EXPOSE 4434/udp
ENTRYPOINT ["/barking-push"]
# The configuration is mounted read-only.
CMD ["run", "--config", "/etc/barking-push/barking-push.toml"]
