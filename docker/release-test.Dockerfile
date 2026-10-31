# Test image for the signing and verification scripts (scripts/tests/release-scripts.sh).
# Same Debian bookworm base as the project's other images (pinned digest) and same
# apt snapshot as docker/repro.Dockerfile: minisign and git come from this snapshot.
# git depends on perl, and the snapshot lacks the base image's (newer) perl-base:
# perl-base is therefore brought down to the snapshot's version.
FROM debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3

ARG DEBIAN_SNAPSHOT=20261001T000000Z
RUN rm -f /etc/apt/sources.list /etc/apt/sources.list.d/* \
 && printf '%s\n' \
      "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}/ bookworm main" \
      "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}/ bookworm-security main" \
      > /etc/apt/sources.list \
 && printf 'Acquire::Check-Valid-Until "false";\nAcquire::Retries "5";\n' > /etc/apt/apt.conf.d/99snapshot \
 && apt-get update \
 && apt-get install -y --no-install-recommends --allow-downgrades minisign git \
      perl-base=5.36.0-7+deb12u3 \
 && rm -rf /var/lib/apt/lists/*
