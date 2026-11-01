# Offline signing/verification integration tests; no compiler or GitHub token.
FROM alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
COPY apk/install.sh apk/release.txt /etc/barking-apk/
RUN sh /etc/barking-apk/install.sh /etc/barking-apk/release.txt
