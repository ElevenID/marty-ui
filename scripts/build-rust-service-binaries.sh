#!/bin/sh
set -eu

# Build the single KMS-only public service binary set.
case "${1:-}" in
  default) shift; set -- ;;
  *) echo "expected default build mode" >&2; exit 2 ;;
esac

exec cargo build --locked --release "$@" \
  -p marty-event-stream --bin marty-event-stream \
  -p marty-gateway --bin marty-gateway \
  -p marty-revocation-profile --bin marty-revocation-profile \
  -p marty-signing-keys --bin marty-signing-keys --bin marty-passport-callback-signer --bin marty-passport-callback-signer-supported \
  -p marty-notification --bin marty-notification \
  -p marty-flow --bin marty-flow \
  -p marty-organization --bin marty-organization --bin marty-passport-acceptance-api-key \
  -p marty-auth --bin marty-auth \
  -p marty-credential-template --bin marty-credential-template \
  -p marty-presentation-policy --bin marty-presentation-policy --bin marty-verifier-positive-gate \
  -p marty-trust-profile --bin marty-trust-profile \
  -p marty-applicant --bin marty-applicant \
  -p marty-device-registration --bin marty-device-registration \
  -p marty-verification-service --bin marty-verification-service \
  -p marty-issuance-service --bin marty-issuance-service --bin marty-canvas-sync-worker --bin marty-passport-beta-bureau --bin marty-passport-provider-ingress \
  -p marty-deployment-profile --bin marty-deployment-profile \
  -p marty-compliance-profile --bin marty-compliance-profile
