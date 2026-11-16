#!/usr/bin/env bash
# Reviewed ownership and exact test-only proofs; no API pagination/truncation.
set -euo pipefail

all=false
ui=false
website=false
website_only=false
python=false
rust=false
rust_runtime=false
rust_matrix='["canvas","contracts","selfhost"]'
openbao=false
rollback_test_only=false
didcomm_release_test_only=false
k8s_policy_test_only=false
release=false
verification=false
security=false

# Observation only. Neither this result nor a missing diff may
# narrow the mandatory merge-group matrix. This broad candidate
# closure precedes any future historical-oracle tier decision.
report_historical_input_shadow() {
  local event="$1" diff_status="$2"
  shift 2
  local candidate=unknown path
  if [[ "$diff_status" == proved ]]; then
    candidate=false
    for path in "$@"; do
      case "$path" in
        scripts/*|contracts/*|rust/services/issuance/migrations/*|rust/services/issuance/tests/support/*|rust/crates/canvas-acceptance/tests/*|rust/crates/flow-acceptance/tests/*|.github/workflows/ci.yml)
          candidate=true
          ;;
      esac
    done
  fi
  printf 'MARTY_CI_HISTORICAL_INPUT_SHADOW_V1 {"event":"%s","diff":"%s","path_count":%s,"candidate":"%s","authority":"shadow-only"}\n' \
    "$event" "$diff_status" "$#" "$candidate" >&2
}

# Fail closed before selecting work: the tested tree and event identities must
# be exact, and a comparison event must have an authenticated complete diff.
python3 scripts/ci/affected_components.py identity
[[ "$(git rev-parse --verify HEAD)" == "$SOURCE_SHA" ]]
changed_files=()
if [[ "$EVENT_NAME" == pull_request || "$EVENT_NAME" == merge_group ]]; then
  git fetch --no-tags --depth=1 origin "$BASE_SHA"
  changed_paths_file="$RUNNER_TEMP/ci-changed-paths"
  git diff --name-only -z --no-renames "$BASE_SHA" HEAD > "$changed_paths_file"
  mapfile -d '' -t changed_files < "$changed_paths_file"
  report_historical_input_shadow "$EVENT_NAME" proved "${changed_files[@]}"
  website_only=$(python3 scripts/ci/affected_components.py website-only --paths-file "$changed_paths_file")
fi

if [[ "$website_only" == true ]]; then
  website=true
elif [[ "$EVENT_NAME" != pull_request ]]; then
  all=true
else
  # Only the regular rollback test leaf gets root-pytest feedback.
  if [[ "$EVENT_NAME" == pull_request &&
        ${#changed_files[@]} -eq 1 &&
        "${changed_files[0]}" == tests/test_beta_worker_launch_rollback.py &&
        -f tests/test_beta_worker_launch_rollback.py &&
        ! -L tests/test_beta_worker_launch_rollback.py ]]; then
    rollback_test_only=true
  fi
  # These exact DIDComm policy tests are collected by root release
  # pytest, not by a service or image. Only one regular test source
  # may narrow a PR; moves, deletion, mixed changes and untrusted
  # checkout entries retain the complete plan.
  if [[ "$EVENT_NAME" == pull_request &&
        ${#changed_files[@]} -eq 1 ]]; then
    case "${changed_files[0]}" in
      tests/test_didcomm_native_consumer_ownership.py)
        if [[ -f "${changed_files[0]}" && ! -L "${changed_files[0]}" ]]; then
          didcomm_release_test_only=true
        fi
        ;;
    esac
  fi
  # These six exact policy-test leaves have one root-pytest owner.
  # Only a nonempty PR of regular, unique files may use its bounded
  # source suite; manifests, scripts and protected heads stay full.
  if [[ "$EVENT_NAME" == pull_request &&
        ${#changed_files[@]} -gt 0 ]]; then
    k8s_policy_test_only=true
    seen_k8s_policy_paths=()
    for path in "${changed_files[@]}"; do
      case "$path" in
        tests/test_issuance_consumer_bindings.py|tests/test_kubernetes_app_service_coverage.py|tests/test_check_kubernetes_services_release.py|tests/test_kubernetes_token_hmac_secret.py|tests/test_passport_supported_k8s_deployment.py|tests/test_passport_supported_consumer_routing.py) ;;
        *) k8s_policy_test_only=false; break ;;
      esac
      if [[ ! -f "$path" || -L "$path" ]]; then
        k8s_policy_test_only=false
        break
      fi
      for previous in "${seen_k8s_policy_paths[@]}"; do
        if [[ "$path" == "$previous" ]]; then
          k8s_policy_test_only=false
          break
        fi
      done
      seen_k8s_policy_paths+=("$path")
    done
  fi
  leaf_only=false
  leaf_candidate=true
  if (( ${#changed_files[@]} == 0 )); then
    leaf_candidate=false
  fi
  for path in "${changed_files[@]}"; do
    case "$path" in
      rust/services/issuance/src/*_tests.rs|rust/crates/oid4vp-contract/tests/contract_vectors.rs|rust/crates/oid4vp-contract/tests/transport_metadata.rs) ;;
      *) leaf_candidate=false; break ;;
    esac
  done
  if [[ "$leaf_candidate" == true ]]; then
    verified_leaves_file="$RUNNER_TEMP/ci-verified-test-leaves"
    if python3 tests/test_rust_test_only_docker_context.py \
      --emit-verified-leaves > "$verified_leaves_file"; then
      mapfile -d '' -t owned_leaves < "$verified_leaves_file"
      leaf_only=true
      for path in "${changed_files[@]}"; do
        owned=false
        for leaf in "${owned_leaves[@]}"; do
          if [[ "$path" == "$leaf" ]]; then
            owned=true
            break
          fi
        done
        if [[ "$owned" != true ]]; then
          leaf_only=false
          break
        fi
      done
    fi
  fi
  # Exact cfg(test) Issuance leaves with no separately owned DB cases.
  # Passport's ignored PostgreSQL cases stay on the broader route.
  renewal_unit_test_only=false
  if [[ "$leaf_only" == true &&
        "$EVENT_NAME" == pull_request ]]; then
    renewal_unit_test_only=true
    for path in "${changed_files[@]}"; do
      case "${path#rust/services/issuance/src/}" in
        canvas_operation_http_prepared_tests.rs|canvas_sync_provider_http_tests.rs|canvas_sync_processor_tests.rs|canvas_sync_worker_retry_tests.rs|canvas_sync_worker_renewal_tests.rs|initiation_didcomm/tests/initiation_didcomm_renewal_tests.rs|python_format_tests.rs|signing_http_projection_tests.rs|signing_http_response_tests.rs|token_rate_limit_http_tests.rs) ;;
        *) renewal_unit_test_only=false; break ;;
      esac
    done
  fi
  # These exact test-source cohorts and their six-context/sole-owner
  # proofs live in one checked-out verifier. Malformed, mixed, and
  # unproved diffs keep the complete Rust matrix.
  worker_test_only=false
  flow_test_only=false
  selfhost_test_only=false
  acceptance_candidate=true
  if [[ "$EVENT_NAME" == pull_request &&
        ${#changed_files[@]} -gt 0 ]]; then
    for path in "${changed_files[@]}"; do
      case "$path" in
        rust/crates/canvas-worker-acceptance/tests/*|rust/crates/flow-acceptance/tests/*|rust/crates/selfhost-acceptance/tests/*) ;;
        *) acceptance_candidate=false; break ;;
      esac
    done
  else
    acceptance_candidate=false
  fi
  # This prefix can only reject; the checked-out exact-file and
  # six-context proofs below alone grant a narrower PR matrix.
  if [[ "$acceptance_candidate" == true ]]; then
    if acceptance_lane=$(printf '%s\0' "${changed_files[@]}" |
      python3 tests/test_rust_test_only_docker_context.py \
        --select-acceptance-test-lane); then
      case "$acceptance_lane" in
        worker) worker_test_only=true ;;
        flow) flow_test_only=true ;;
        selfhost) selfhost_test_only=true ;;
      esac
    fi
  fi
  contract_test_only=false
  contract_test_candidate=true
  if [[ "$EVENT_NAME" != pull_request || ${#changed_files[@]} -eq 0 ]]; then
    contract_test_candidate=false
  fi
  for path in "${changed_files[@]}"; do
    case "$path" in
      rust/crates/service-acceptance/tests/*|rust/services/signing-keys/tests/*) ;;
      *) contract_test_candidate=false; break ;;
    esac
  done
  # The prefix only rejects; exact ownership and all Rust contexts grant.
  if [[ "$contract_test_candidate" == true ]] &&
     printf '%s\0' "${changed_files[@]}" |
       python3 tests/test_rust_test_only_docker_context.py \
         --select-contract-tests; then
    contract_test_only=true
  fi
  for path in "${changed_files[@]}"; do
    case "$path" in
      rust/services/issuance/src/canvas_sync_processor_contract.md)
        # include_str! makes this documentation a compiler input.
        rust=true
        ;;
      SELFHOST_BUNDLE.md)
        # The self-host bundle ships this file as a package asset.
        rust=true
        ;;
      *.md|docs/*|.github/ISSUE_TEMPLATE/*)
        ;;
      ui/index.html)
        # The native installer validation embeds the entry document.
        ui=true
        rust=true
        security=true
        ;;
      ui/*|demo-apps/*)
        ui=true
        security=true
        ;;
      services/Dockerfile|services/Dockerfile.dockerignore|services/entrypoint.sh|services/auth/assets/*)
        rust=true
        python=true
        security=true
        ;;
      services/*|packages/*|requirements-services.txt)
        python=true
        security=true
        ;;
      contracts/canvas-worker-provider-recovery-current-inputs.json)
        # This overlay has only release-pytest consumers. The
        # inherited REST record and every script/scenario
        # input retain their existing Rust/release or broad owner.
        release=true
        ;;
      contracts/canvas-*-current-inputs.json)
        # Only immediate-child CI input records use the reviewed
        # Docker exclusion. A nested lookalike is unknown input.
        if [[ "$path" == contracts/*/* ]]; then
          all=true
        else
          rust=true
          release=true
        fi
        ;;
      contracts/canvas-worker-oracle-producers.json|contracts/canvas-worker-oracle-script-imports.json|contracts/canvas-worker-tier-obligations.json|contracts/python-value-fast-obligations.json|contracts/canvas-renewal-profile-obligations.json)
        # Retain Rust qualification for contract metadata and also
        # run release-collected evidence/obligation ownership checks.
        rust=true
        release=true
        ;;
      tests/test_canvas_worker_oracle_producer_inventory.py|tests/test_canvas_worker_oracle_script_closure.py|tests/test_canvas_worker_startup_input_evidence.py|tests/test_canvas_worker_rest_input_evidence.py|tests/test_canvas_worker_provider_signals_input_evidence.py|tests/test_canvas_worker_timeout_input_evidence.py|tests/test_canvas_worker_retry_after_input_evidence.py|tests/test_canvas_json_depth_current_inputs.py|tests/test_canvas_operations_input_current_inputs.py|tests/test_canvas_worker_validation_tier.py|tests/test_python_value_fast_obligations.py|tests/test_canvas_renewal_profile_obligations.py)
        # These exact test-only sources run in release pytest. Their
        # manifest inputs retain the Rust discovery/evidence owner;
        # implementation scripts, unknown siblings, and corpora
        # remain conservatively broad.
        release=true
        ;;
      rust/services/flow/src/request_object.rs|rust/services/flow/src/verification_submission.rs|rust/services/flow/src/http_verification.rs|rust/services/flow/src/http_providers.rs|rust/services/flow/src/providers.rs|rust/services/flow/src/connections.rs|rust/services/flow/src/config.rs|rust/services/flow/tests/haip_*|rust/services/signing-keys/src/flow_envelope.rs|rust/services/signing-keys/src/http.rs|rust/services/signing-keys/src/http/*.rs|rust/services/signing-keys/src/kms.rs|rust/services/signing-keys/src/kms_*.rs|rust/services/signing-keys/src/config.rs|rust/services/signing-keys/src/main.rs|rust/crates/oid4vp-contract/src/haip_key.rs)
        # These owners can change the live HAIP custody path even
        # when the OpenBao plugin source is untouched.
        rust=true
        openbao=true
        security=true
        ;;
      contracts/web-surface-routes.json|contracts/website-source-ownership.json|contracts/protocol-support-catalog.json)
        # These inputs define emitted UI ownership and customer/public routes.
        all=true
        ;;
      rust/*|proto/*|contracts/*)
        rust=true
        ;;
      openbao/*|docker/openbao-*|keycloak/openbao-provider/*|scripts/probe_keycloak_remote_rs256.py|scripts/sql/keycloak-kms-only-verify.sql)
        openbao=true
        rust=true
        security=true
        ;;
      release/stack-lock.json|.github/workflows/ci.yml|.github/actions/*|docker-compose*.yml|k8s/*)
        all=true
        ;;
      release/*|scripts/stack_tag_gate.py|scripts/release_transaction.py|.github/stack-tag-policy.json)
        release=true
        ;;
      tests/test_stack_tag_gate.py|tests/test_release_transaction.py|tests/test_stack_release_contract.py|tests/test_build_stack_manifest.py|tests/test_prepare_official_beta_release.py|tests/test_stack_pre_promotion.py)
        # The release lane executes the complete root Python test
        # suite. These exact test sources do not enter runtime
        # images; unknown siblings retain the full PR matrix.
        release=true
        ;;
      tests/test_check_release_absent.py|tests/test_github_release_environment_preflight.py|tests/test_release_environment_workflow_contract.py|tests/test_create_local_release_manifest.py|tests/test_local_beta_release_runner.py)
        # These exact release-environment/manifest contract tests
        # also run in the required release lane, not service images.
        release=true
        ;;
      tests/test_sanitize_sccache_stats.py|tests/test_oss_boundary.py|tests/test_public_protocol_documentation.py|tests/test_gateway_public_protocol_contract.py|tests/test_public_vector_execution.py|tests/test_ci_database_groups.py|tests/test_canvas_published_preflight.py|tests/test_rust_ownership.py|tests/test_selfhost_packager_reference.py|tests/test_ci_workflow_performance.py)
        # These test-only policy and fixture guards are collected by
        # the root release pytest step, with no other CI/image owner.
        # Their implementation inputs still retain their own lanes.
        release=true
        ;;
      tests/test_kubernetes_resolved_runtime.py|tests/test_base_native_runtime_fixture.py|tests/test_envoy_native_configuration.py|tests/test_flow_public_startup.py|tests/test_selfhost_runtime_model.py|tests/test_passport_supported_rust_model.py|tests/test_passport_supported_compose_ownership.py|tests/test_ci_canvas_compile_scope.py)
        # These exact fixture-policy test sources run in root release
        # pytest. Renderers, acceptance targets, and unknown siblings
        # retain the broad source-input selection below.
        release=true
        ;;
      tests/test_issuance_rust_candidate.py|tests/test_kubernetes_native_issuance.py|tests/test_shared_rust_service_image.py|tests/test_passport_supported_provisioning_producer.py|tests/test_issuance_passport_native_compose.py|tests/test_conformance_native.py|tests/test_passport_supported_disposable_compose.py|tests/test_gateway_rust_cutover.py)
        # These exact model/Compose policy test sources are collected
        # by root release pytest, not runtime images or another CI
        # job. Production inputs and unknown test siblings stay broad.
        release=true
        ;;
      tests/test_issuance_consumer_bindings.py|tests/test_kubernetes_app_service_coverage.py|tests/test_check_kubernetes_services_release.py|tests/test_kubernetes_token_hmac_secret.py|tests/test_passport_supported_k8s_deployment.py|tests/test_passport_supported_consumer_routing.py)
        # These exact Kubernetes/consumer policy test sources run in
        # root release pytest. Their source scripts, manifests, and
        # unknown test siblings keep their existing broad selection.
        release=true
        ;;
      tests/test_signing_response_reference.py|tests/test_token_rate_reference.py|tests/test_canvas_url_template_reference.py)
        # Frozen-reference guards are collected by root release
        # pytest only. Their corpora and native Rust consumers keep
        # the existing Rust selection; capture scripts stay broad.
        release=true
        ;;
      tests/test_beta_worker_launch_rollback.py)
        if [[ "$rollback_test_only" == true ]]; then
          release=true
          security=true
        else
          all=true
        fi
        ;;
      tests/test_didcomm_native_consumer_ownership.py)
        if [[ "$didcomm_release_test_only" == true ]]; then
          release=true
        else
          all=true
        fi
        ;;
      scripts/ci/canvas_oracle_current_inputs.py)
        # Only root release-pytest Canvas input guards import this
        # helper. Capture scripts, manifest inputs, and unknown
        # script siblings keep their existing broader selection.
        release=true
        ;;
      .github/workflows/verification-candidate-*.yml|tests/test_verification_candidate_*.py)
        verification=true
        release=true
        ;;
      scripts/register-canvas-oss-runner.ps1|scripts/runner-routing-label-policy.ps1|scripts/runner-host-capacity-policy.ps1|scripts/setup-canvas-oss-runner.ps1|tests/test_runner_routing_labels.py|tests/test_canvas_oss_runner_quarantine.py)
        # These host-registration inputs are checked by the root
        # release pytest suite; they are not public image inputs.
        # Manual self-hosted workflows retain their own preflights.
        release=true
        ;;
      tests/*|scripts/*|.github/workflows/*|.github/codeql/*|.dockerignore)
        all=true
        ;;
      *)
        # Unknown paths deliberately receive the complete suite.
        all=true
        ;;
    esac
  done
fi

if [[ "$all" == true ]]; then
  ui=true
  python=true
  rust=true
  openbao=true
  release=true
  verification=true
  security=true
fi

if [[ "$ui" == true ]]; then
  website=true
fi

if [[ "$rust" == true ]]; then
  rust_runtime=true
  if [[ "${worker_test_only:-false}" == true && "$all" == false &&
        "$EVENT_NAME" == pull_request ]]; then
    rust_runtime=false
    rust_matrix='["worker"]'
  elif [[ "${flow_test_only:-false}" == true && "$all" == false &&
          "$EVENT_NAME" == pull_request ]]; then
    rust_runtime=false
    rust_matrix='["flow"]'
  elif [[ "${selfhost_test_only:-false}" == true && "$all" == false &&
          "$EVENT_NAME" == pull_request ]]; then
    rust_runtime=false
    rust_matrix='["selfhost"]'
  elif [[ "${contract_test_only:-false}" == true && "$all" == false &&
          "$EVENT_NAME" == pull_request ]]; then
    rust_runtime=false
    rust_matrix='["contracts"]'
  elif [[ "${renewal_unit_test_only:-false}" == true && "$all" == false &&
          "$EVENT_NAME" == pull_request ]]; then
    rust_runtime=false
    rust_matrix='["renewal-unit"]'
  elif [[ "${leaf_only:-false}" == true && "$all" == false &&
        "$EVENT_NAME" == pull_request ]]; then
    rust_runtime=false
    rust_matrix='["contracts"]'
  fi
fi

{
  printf 'all=%s\n' "$all"
  printf 'ui=%s\n' "$ui"
  printf 'website=%s\n' "$website"
  printf 'website_only=%s\n' "$website_only"
  printf 'python=%s\n' "$python"
  printf 'rust=%s\n' "$rust"
  printf 'rust_runtime=%s\n' "$rust_runtime"
  printf 'rust_matrix=%s\n' "$rust_matrix"
  printf 'openbao=%s\n' "$openbao"
  printf 'rollback_test_only=%s\n' "$rollback_test_only"
  printf 'didcomm_release_test_only=%s\n' "$didcomm_release_test_only"
  printf 'k8s_policy_test_only=%s\n' "$k8s_policy_test_only"
  printf 'release=%s\n' "$release"
  printf 'verification=%s\n' "$verification"
  printf 'security=%s\n' "$security"
} >> "$GITHUB_OUTPUT"

python3 scripts/ci/affected_components.py emit
