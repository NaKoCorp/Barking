# Security policy

Barking is a **prototype**: it has not been externally audited (see the warning in the [README](README.md)). Reports are still very welcome, and they shape the audit that must come before any wider use.

## Reporting a vulnerability

Please **do not open a public issue**. Report privately through GitHub:

1. Go to the [Security tab](https://github.com/NaKoCorp/Barking/security) of the repository.
2. Click **Report a vulnerability** and describe the issue, how to reproduce it, and its impact.

You should get an answer within a week. Once a fix is ready, the report is published as a GitHub security advisory, crediting you unless you prefer otherwise.

## Scope

In scope: everything in this repository, in particular

- the protocol and its cryptography (`barking-core`, `barking-packet`, `barking-proto`): confidentiality, authentication, metadata leaks;
- the nodes and the push relay (`barking-node`, `barking-dht`, `barking-push`): remote crashes, resource exhaustion, ways to link a mailbox to a user;
- the clients (`barking-cli`, `barking-net`, `barking-ffi`, the iOS app in `apple/`): local storage, key handling;
- the release process: reproducible builds and GitHub provenance attestations (`scripts/`, `.github/workflows/`).

Out of scope: findings that need a compromised device, and denial of service by sheer volume against a single node.

## Supported versions

Only the `main` branch and the latest release are supported.
