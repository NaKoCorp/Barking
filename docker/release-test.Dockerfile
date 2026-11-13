# Offline integration tests of the release scripts; no compiler, no GitHub token.
FROM alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
COPY apk/install.sh apk/release.txt /etc/barking-apk/
RUN sh /etc/barking-apk/install.sh /etc/barking-apk/release.txt
