# Image du test des scripts de signature et de vérification (scripts/tests/release-scripts.sh).
# Même base Debian bookworm que les autres images du projet (empreinte épinglée) et même
# snapshot apt que docker/repro.Dockerfile : minisign et git viennent de ce snapshot.
# git dépend de perl, dont le snapshot n'a pas le perl-base (plus récent) de l'image de base :
# perl-base est donc ramené à la version du snapshot.
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
