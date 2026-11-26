#!/bin/sh
set -eu

# Build the single KMS-only public service binary set.
case "${1:-}" in
  default) shift ;;
  *) echo "expected default build mode" >&2; exit 2 ;;
esac

# Local source builders may request deterministic, offline compiler telemetry.
# Reject package, feature, profile and arbitrary Cargo overrides.
for option in "$@"; do
  case "$option" in
    --offline|-j1|--message-format=json) ;;
    *) echo "unsupported default build option" >&2; exit 2 ;;
  esac
done

cargo build --locked --release "$@" \
  -p marty-event-stream --bin marty-event-stream \
  -p marty-gateway --bin marty-gateway \
  -p marty-revocation-profile --bin marty-revocation-profile \
  -p marty-signing-keys --bin marty-signing-keys --bin marty-passport-callback-signer --bin marty-passport-callback-signer-supported \
  -p marty-notification --bin marty-notification \
  -p marty-flow --bin marty-flow \
  -p marty-organization --bin marty-organization --bin marty-passport-acceptance-api-key --bin marty-installer-organization-api-key \
  -p marty-auth --bin marty-auth \
  -p marty-credential-template --bin marty-credential-template \
  -p marty-presentation-policy --bin marty-presentation-policy --bin marty-verifier-positive-gate \
  -p marty-trust-profile --bin marty-trust-profile \
  -p marty-applicant --bin marty-applicant \
  -p marty-device-registration --bin marty-device-registration \
  -p marty-verification-service --bin marty-verification-service \
  -p marty-issuance-service --bin marty-issuance-service --bin marty-passport-beta-bureau --bin marty-passport-provider-ingress \
  -p marty-passport-keyless-edge --bin marty-passport-keyless-edge --bin marty-passport-tls-bootstrap --bin marty-feature-identity-bootstrap --bin marty-oidf-keyless-edge --bin marty-acme-http01 \
  -p marty-keyless-grpc-bridge --bin marty-keyless-grpc-bridge \
  -p marty-deployment-profile --bin marty-deployment-profile \
  -p marty-compliance-profile --bin marty-compliance-profile

# Approval and lifecycle commands are separate hosts with separate database
# authorities. Keep both in the authenticated services image; runtime selection
# never imports an unqualified host binary.
cargo build --locked --release "$@" -p marty-delegated-authority \
  --bin marty-delegation-approval --bin marty-delegation-commands

# Keep the delegated-use host on its own normal (non-test) Cargo feature graph.
exec cargo build --locked --release "$@" -p marty-delegated-use --bin marty-delegated-use
