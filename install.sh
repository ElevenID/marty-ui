#!/bin/sh
# GitHub-hosted bootstrap. Keep all execution inside main so incomplete piped
# downloads cannot start installation. The signed operator is verified before
# execution; it verifies remaining payloads before runtime provisioning.
main() (
    set -eu
    umask 077
    fail() { printf 'Marty installer: %s\n' "$*" >&2; exit 1; }
    usage() {
        printf '%s\n' \
            'Usage: install.sh [--check-host] [--channel nightly|stable | --version TAG | --candidate-test NIGHTLY_TAG] [--install-dir PATH] [--foundation-file PATH] [--hosting-file PATH] [--acme-staging-roots PATH] [--yes]' \
            'Supported host: Linux amd64, a regular non-root user, no-new-privileges, and an already-running rootless Docker daemon.' \
            'Run a downloaded copy with: /usr/bin/setpriv --no-new-privs -- sh /absolute/install.sh [options]' \
            '--check-host checks bootstrap tools, platform, process privileges, and rootless Docker connectivity, then exits without downloads or installation.' \
            'It creates and removes a private temporary Docker configuration. It does not check Compose, resources, images, release availability, or installation readiness.' \
            '--candidate-test requires an exact published nightly tag and grants no Ready status; --channel and --version require signed installer admission.' \
            'Managed OpenBao is the default; --foundation-file is optional. Host setup is separate: the installer does not use sudo or install OS packages.'
    }
    # Candidate rootless entry must not execute even platform probes with
    # inherited root identity, capabilities, or privilege-gaining exec rights.
    # This uses shell builtins before any external command in that path.
    require_rootless_process() {
        [ -r /proc/self/status ] || fail 'Linux /proc/self/status is required; only Linux amd64 is supported'
        seen_uid= seen_gid= seen_nnp= seen_eff= seen_prm= seen_amb=
        while read -r key first second third fourth extra; do
            case "$key" in
                Uid:)
                    [ -z "$seen_uid" ] && [ -z "$extra" ] && [ -n "$first" ] &&
                        [ "$first" = "$second" ] && [ "$first" = "$third" ] &&
                        [ "$first" = "$fourth" ] && [ "$first" != 0 ] || fail 'Rootless process UID differs or is root; use a regular non-root login without sudo'
                    seen_uid=$first ;;
                Gid:)
                    [ -z "$seen_gid" ] && [ -z "$extra" ] && [ -n "$first" ] &&
                        [ "$first" = "$second" ] && [ "$first" = "$third" ] &&
                        [ "$first" = "$fourth" ] && [ "$first" != 0 ] || fail 'Rootless process GID differs or is root; use a regular non-root login without sudo'
                    seen_gid=$first ;;
                NoNewPrivs:)
                    [ -z "$seen_nnp" ] && [ "$first" = 1 ] && [ -z "$second" ] ||
                        fail 'Rootless trial requires no-new-privileges; run the whole command under /usr/bin/setpriv --no-new-privs -- without sudo (see --help)'
                    seen_nnp=1 ;;
                CapEff:|CapPrm:|CapAmb:)
                    case "$first" in 0000000000000000) ;; *) fail 'Rootless process has capabilities; use a regular login with no effective, permitted, or ambient capabilities' ;; esac
                    [ -z "$second" ] || fail 'Rootless capability record differs'
                    case "$key" in
                        CapEff:) [ -z "$seen_eff" ] || fail 'Repeated capability record'; seen_eff=1 ;;
                        CapPrm:) [ -z "$seen_prm" ] || fail 'Repeated capability record'; seen_prm=1 ;;
                        CapAmb:) [ -z "$seen_amb" ] || fail 'Repeated capability record'; seen_amb=1 ;;
                    esac ;;
            esac
        done < /proc/self/status || fail 'Linux process privilege state unavailable'
        [ -n "$seen_uid" ] && [ -n "$seen_gid" ] && [ "$seen_nnp" = 1 ] &&
            [ "$seen_eff" = 1 ] && [ "$seen_prm" = 1 ] && [ "$seen_amb" = 1 ] ||
            fail 'Rootless process privilege state incomplete'
    }
    # Host-specific behavior stays behind the selected platform adapter.
    linux_required_tools() {
        for tool in curl sha256sum mktemp tar gzip chmod rm wc cut grep docker mkdir env id; do
            command -v "$tool" >/dev/null 2>&1 || fail "Required tool is missing: $tool; install trusted host prerequisites before retrying"
        done
    }
    linux_rootless_preflight() {
        select_docker_binary
        uid=$(id -u) || fail 'Installer UID unavailable'
        case "$uid" in ''|0|*[!0-9]*) fail 'Rootless installer UID invalid' ;; esac
        [ "$uid" = "$seen_uid" ] || fail 'Installer UID changed'
        [ -z "${DOCKER_CONTEXT:-}" ] || fail 'Docker context override is refused for rootless trial; unset DOCKER_CONTEXT and use the same-user rootless socket'
        docker_endpoint="unix:///run/user/$uid/docker.sock"
        [ -z "${DOCKER_HOST:-}" ] || [ "$DOCKER_HOST" = "$docker_endpoint" ] ||
            fail 'Docker endpoint differs from user-owned rootless socket'
        unset DOCKER_CONTEXT DOCKER_TLS_VERIFY DOCKER_CERT_PATH DOCKER_API_VERSION
        export DOCKER_HOST="$docker_endpoint"
        isolated_docker info >/dev/null 2>&1 || fail "User-owned rootless Docker Engine unavailable at $docker_endpoint; start the existing rootless daemon for this user before retrying"
        security_options=$(isolated_docker info --format '{{range .SecurityOptions}}{{println .}}{{end}}') ||
            fail 'Rootless Docker mode unavailable'
        [ "$(printf '%s\n' "$security_options" | grep -cx 'name=rootless' || :)" = 1 ] ||
            fail 'Exact rootless Docker mode required'
        if printf '%s\n' "$security_options" | grep -Eq '^name=userns(,|$)|^name=rootless,'; then
            fail 'Ambiguous Docker user namespace mode'
        fi
        docker_engine_id=$(isolated_docker info --format '{{.ID}}') || fail 'Docker Engine identity unavailable'
        [ -n "$docker_engine_id" ] || fail 'Docker Engine identity unavailable'
    }
    select_docker_binary() {
        docker_bin=$(command -v docker) || fail 'Docker client unavailable'
        case "$docker_bin" in /*) ;; *) fail 'Docker client must have an absolute path' ;; esac
    }
    isolated_docker() {
        env -i PATH=/usr/bin:/bin HOME="$stage/home" DOCKER_CONFIG="$stage/config" \
            DOCKER_HOST="$docker_endpoint" "$docker_bin" "$@"
    }
    linux_digest() { sha256sum < "$1" | cut -d ' ' -f 1; }
    select_platform() {
        host_os=$(uname -s) || fail 'Cannot detect host operating system'
        host_arch=$(uname -m) || fail 'Cannot detect host architecture'
        # Each supported adapter owns the complete, reviewed trust-anchor tuple.
        # Never construct verifier URLs or hashes from untrusted host strings.
        unset platform operator_asset requirements preflight digest_adapter jq_url jq_sha jq_size
        unset cosign_url cosign_sha cosign_size gh_url gh_sha gh_size gh_member
        case "$host_os:$host_arch" in
            Linux:x86_64|Linux:amd64)
                platform=linux/amd64
                operator_asset=marty-deploy-linux-amd64
                requirements=linux_required_tools
                preflight=linux_rootless_preflight
                digest_adapter=linux_digest
                jq_url=https://github.com/jqlang/jq/releases/download/jq-1.8.1/jq-linux-amd64
                jq_sha=020468de7539ce70ef1bceaf7cde2e8c4f2ca6c3afb84642aabc5c97d9fc2a0d
                jq_size=2255816
                cosign_url=https://github.com/sigstore/cosign/releases/download/v3.1.4/cosign-linux-amd64
                cosign_sha=424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa
                cosign_size=145688404
                gh_url=https://github.com/cli/cli/releases/download/v2.103.2/gh_2.103.2_linux_amd64.tar.gz
                gh_sha=62ccf747115ddc61237efffdde66a3c8f70ba249433dc64f70801089b59c59c8
                gh_size=15031001
                gh_member=gh_2.103.2_linux_amd64/bin/gh
                ;;
            *) fail "Unsupported platform: $host_os/$host_arch. Currently supported: Linux amd64" ;;
        esac
    }
    channel=nightly
    version=
    selection=
    destination=
    foundation_file=
    hosting_file=
    acme_staging_roots=
    yes=false
    check_host=false
    complete=false
    candidate_test=false
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --bootstrap-complete) [ "$#" -eq 1 ] || fail 'Invalid bootstrap terminator'; complete=true; shift ;;
            --help|-h) usage; exit 0 ;;
            --yes) yes=true; shift ;;
            --check-host) check_host=true; shift ;;
            --channel|--version|--candidate-test|--install-dir|--foundation-file|--hosting-file|--acme-staging-roots)
                [ "$#" -ge 2 ] && [ -n "$2" ] || fail "Missing value for $1"
                case "$2" in --*) fail "Missing value for $1" ;; esac
                case "$1" in
                    --channel) [ -z "$selection" ] || fail 'Choose one release selector'; channel=$2; selection=channel ;;
                    --version) [ -z "$selection" ] || fail 'Choose one release selector'; version=$2; selection=version ;;
                    --candidate-test) [ -z "$selection" ] || fail 'Choose one release selector'; version=$2; selection=candidate; candidate_test=true ;;
                    --install-dir) [ -z "$destination" ] || fail 'Repeated installation directory'; destination=$2 ;;
                    --foundation-file) [ -z "$foundation_file" ] || fail 'Repeated foundation input'; foundation_file=$2 ;;
                    --hosting-file) [ -z "$hosting_file" ] || fail 'Repeated hosting input'; hosting_file=$2 ;;
                    --acme-staging-roots) [ -z "$acme_staging_roots" ] || fail 'Repeated ACME staging roots input'; acme_staging_roots=$2 ;;
                esac
                shift 2 ;;
            *) fail "Unknown option: $1" ;;
        esac
    done
    [ "$complete" = true ] || fail 'Incomplete bootstrap download; retry the original command'
    case "$channel" in nightly|stable) ;; *) fail 'Channel must be nightly or stable' ;; esac
    require_rootless_process
    select_platform
    if [ -n "$version" ]; then
        printf '%s\n' "$version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-nightly\.20[0-9]{6}\.[1-9][0-9]*)?$' || fail 'Invalid version'
    fi
    if [ "$candidate_test" = true ]; then
        case "$version" in *-nightly.*) ;; *) fail 'Candidate testing requires an exact nightly tag' ;; esac
    fi
    # Check dependencies before creating staging or installing its cleanup trap.
    "$requirements"
    stage=
    create_stage() {
        stage=$(mktemp -d /tmp/marty-installer.XXXXXXXX) || fail 'Cannot create private download directory; /tmp must be writable with enough free space'
        trap 'rm -rf -- "$stage"' EXIT
        trap 'exit 130' INT
        trap 'exit 143' TERM
        mkdir "$stage/config" "$stage/cache" "$stage/home"
    }
    create_stage
    # The first Docker observation must not read ambient context or plugin
    # configuration. The operator uses its own isolated configuration too.
    export DOCKER_CONFIG="$stage/config"
    "$preflight"
    if [ "$check_host" = true ]; then
        printf '%s\n' \
            "Marty bootstrap host checks passed: Linux amd64, non-root UID $uid, no-new-privileges, zero effective/permitted/ambient capabilities, and rootless Docker connectivity." \
            'Only bootstrap tools and host checks ran; Compose, resources, images, release availability, and installation readiness were not checked.' \
            'The private temporary Docker configuration will be removed on exit. No downloads, Docker mutations, or installation were performed.'
        return
    fi
    # Never consume or send a caller's GitHub credentials during public bootstrap.
    unset GH_TOKEN GITHUB_TOKEN GH_ENTERPRISE_TOKEN GITHUB_ENTERPRISE_TOKEN GH_DEBUG
    export GH_CONFIG_DIR="$stage/config" GH_HOST=github.com GH_PROMPT_DISABLED=1
    export XDG_CACHE_HOME="$stage/cache" COSIGN_YES=true
    fetch() {
        # curlrc is disabled; restrict both the initial and redirected protocols.
        if download_status=$(curl -q --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
            --connect-timeout 20 --max-time 600 --retry 2 --max-filesize "$3" \
            --write-out '%{http_code}' --output "$2" "$1"); then
            :
        else
            case "$download_status" in
                404)
                    case "$1" in
                        https://raw.githubusercontent.com/ElevenID/marty-ui/installer-channel/*)
                            fail 'No public installer channel is available for this selection. An explicitly published nightly may be tested with --candidate-test TAG; normal installation still requires signed admission' ;;
                        https://github.com/ElevenID/marty-ui/releases/download/installer-admission-*/*)
                            fail 'No public signed installer admission is available for this version. --version requires accepted admission; --candidate-test NIGHTLY_TAG is a separate unqualified test path' ;;
                        *) fail 'Required public release asset is unavailable (HTTP 404); check the exact published release tag and its required assets' ;;
                    esac ;;
                401|403|429)
                    fail 'Public download access was denied or rate-limited; check public release access and GitHub anonymous rate limits. This bootstrap does not use GitHub credentials' ;;
                *) fail 'Download failed; check HTTPS connectivity, host CA trust, available temporary space, and public GitHub access' ;;
            esac
        fi
        [ "$(wc -c < "$2")" -le "$3" ] || fail 'Downloaded asset exceeds its size limit'
    }
    digest() { "$digest_adapter" "$1"; }
    pinned() {
        fetch "$1" "$2" "$4"
        [ "$(digest "$2")" = "$3" ] || fail 'Verification tool digest mismatch'
    }
    pinned "$jq_url" "$stage/jq" "$jq_sha" "$jq_size"
    chmod 700 "$stage/jq"
    jq="$stage/jq"
    "$jq" --version >/dev/null 2>&1 || fail 'Pinned jq cannot execute; Linux amd64 and executable temporary storage under /tmp are required'
    verifiers_ready=false
    prepare_verifiers() {
        [ "$verifiers_ready" = false ] || return 0
        # Missing release metadata must not trigger the large verifier downloads.
        pinned "$cosign_url" "$stage/cosign" "$cosign_sha" "$cosign_size"
        pinned "$gh_url" "$stage/gh.tar.gz" "$gh_sha" "$gh_size"
        tar -xzf "$stage/gh.tar.gz" -C "$stage" "$gh_member" || fail 'Cannot unpack the pinned GitHub verifier; check tar, gzip, and available temporary space'
        gh="$stage/$gh_member"
        chmod 700 "$stage/cosign" "$gh"
        verifiers_ready=true
    }
    repo=ElevenID/marty-ui
    base="https://github.com/$repo/releases/download"
    run_field() {
        "$jq" -er --arg key "$2" '.[$key] | select(type == "number" and . > 0 and . < 9007199254740992 and floor == .)' "$1"
    }
    verify() {
        prepare_verifiers
        env -i PATH=/usr/bin:/bin HOME="$stage/home" XDG_CACHE_HOME="$stage/cache" \
            "$stage/cosign" verify-blob "$1" --bundle "$1.sigstore.json" \
            --certificate-identity "https://github.com/$repo/.github/workflows/$2@refs/heads/main" \
            --certificate-oidc-issuer https://token.actions.githubusercontent.com >/dev/null || fail 'Blob signature verification failed; no deployment operator was executed'
        env -i PATH=/usr/bin:/bin HOME="$stage/home" XDG_CACHE_HOME="$stage/cache" \
            GH_CONFIG_DIR="$stage/config" GH_HOST=github.com GH_PROMPT_DISABLED=1 \
            "$gh" attestation verify "$1" --bundle "$1.provenance.jsonl" --repo "$repo" \
            --signer-workflow "$repo/.github/workflows/$2" --source-ref refs/heads/main \
            --source-digest "$3" --deny-self-hosted-runners \
            --predicate-type https://slsa.dev/provenance/v1 --format json > "$1.verified.json" || fail 'Provenance verification failed; no deployment operator was executed'
        "$jq" -e --arg source "$3" \
            --arg signer "https://github.com/$repo/.github/workflows/$2@refs/heads/main" \
            --arg invocation "https://github.com/$repo/actions/runs/$4/attempts/$5" '
            type == "array" and length == 1 and
            (.[0].verificationResult.signature.certificate |
                .issuer == "https://token.actions.githubusercontent.com"
                and .runnerEnvironment == "github-hosted"
                and .sourceRepositoryURI == "https://github.com/ElevenID/marty-ui"
                and .sourceRepositoryIdentifier == "1140864197"
                and .sourceRepositoryDigest == $source
                and .sourceRepositoryRef == "refs/heads/main"
                and .buildSignerURI == $signer
                and .runInvocationURI == $invocation)' "$1.verified.json" >/dev/null || fail 'Verified provenance identity differs from the exact source, workflow, or invocation'
    }
    signed_download() {
        fetch "$1" "$2" "$3"
        fetch "$1.sigstore.json" "$2.sigstore.json" 1048576
        fetch "$1.provenance.jsonl" "$2.provenance.jsonl" 1048576
    }
    if [ "$candidate_test" = true ]; then
        printf '%s\n' 'Marty candidate test: unqualified nightly; installation Ready is not granted.' >&2
        signed_download "$base/$version/installer-inventory.json" "$stage/installer-inventory.json" 65536
        source=$("$jq" -er '.source_sha | select(test("^[0-9a-f]{40}$"))' "$stage/installer-inventory.json")
        build_run=$(run_field "$stage/installer-inventory.json" build_run_id)
        build_attempt=$(run_field "$stage/installer-inventory.json" build_run_attempt)
        "$jq" -e --arg tag "$version" --arg asset "$operator_asset" '
            .schema == "elevenid.installer-inventory/v1" and .repository == "ElevenID/marty-ui"
            and .platform == "linux/amd64" and .release_tag == $tag
            and ([.artifacts[] | select(.name == $asset)] | length == 1)
        ' "$stage/installer-inventory.json" >/dev/null || fail 'Candidate inventory identity differs'
        verify "$stage/installer-inventory.json" nightly-release.yml "$source" "$build_run" "$build_attempt"
        operator_sha=$("$jq" -er --arg asset "$operator_asset" '.artifacts[] | select(.name == $asset) | .sha256 | select(test("^[0-9a-f]{64}$"))' "$stage/installer-inventory.json")
        signed_download "$base/$version/$operator_asset" "$stage/marty-deploy" 536870912
        [ "$(digest "$stage/marty-deploy")" = "$operator_sha" ] || fail 'Candidate operator digest differs'
        verify "$stage/marty-deploy" nightly-release.yml "$source" "$build_run" "$build_attempt"
        chmod 700 -- "$stage/marty-deploy"
        [ "$("$stage/marty-deploy" --build-identity)" = "$source:$version" ] || fail 'Candidate operator build identity differs'
        set -- candidate-test --version "$version" --verified-inventory "$stage/installer-inventory.json" \
            --verification-tools "$stage" --gh-bin "$gh" \
            --docker-host "$docker_endpoint" --docker-engine-id "$docker_engine_id" --docker-bin "$docker_bin" \
            --runtime-profile rootless
        [ -z "$destination" ] || set -- "$@" --install-dir "$destination"
        [ -z "$foundation_file" ] || set -- "$@" --foundation-file "$foundation_file"
        [ -z "$hosting_file" ] || set -- "$@" --hosting-file "$hosting_file"
        [ -z "$acme_staging_roots" ] || set -- "$@" --acme-staging-roots "$acme_staging_roots"
        [ "$yes" = false ] || set -- "$@" --yes
        "$stage/marty-deploy" "$@"
        return
    fi
    # The unsigned pointer locates immutable metadata; it grants no authority.
    # Publishers compare-and-swap one branch commit, never replace release assets.
    select_channel() {
        pointer_url="https://raw.githubusercontent.com/$repo/installer-channel/$channel.json"
        fetch "$pointer_url" "$stage/channel-pointer.json" 65536
        "$jq" -e --arg channel "$channel" '
            type == "object" and keys == ["channel","generation","record_sha256","repository","schema"]
            and .schema == "elevenid.installer-channel-pointer/v1"
            and .repository == "ElevenID/marty-ui" and .channel == $channel
            and (.generation | type == "number" and . > 0 and . < 9007199254740992 and floor == .)
            and (.record_sha256 | type == "string" and test("^[0-9a-f]{64}$"))
        ' "$stage/channel-pointer.json" >/dev/null || fail 'Invalid channel pointer'
        generation=$("$jq" -er '.generation | tostring' "$stage/channel-pointer.json")
        signed_download "$base/installer-channel-$channel-$generation/installer-channel.json" "$stage/channel.json" 65536
        [ "$(digest "$stage/channel.json")" = "$("$jq" -er '.record_sha256' "$stage/channel-pointer.json")" ] || fail 'Channel record differs from pointer'
        [ "$("$jq" -er '.generation | tostring' "$stage/channel.json")" = "$generation" ] || fail 'Channel generation differs from pointer'
    }
    recheck_channel_pointer() {
        fetch "$pointer_url" "$stage/channel-pointer-recheck.json" 65536
        [ "$(digest "$stage/channel-pointer.json")" = "$(digest "$stage/channel-pointer-recheck.json")" ] || fail 'Channel changed during download; retry the original command'
    }
    if [ -z "$version" ]; then
        select_channel
        promotion_source=$("$jq" -er '.promotion_source_sha | select(test("^[0-9a-f]{40}$"))' "$stage/channel.json")
        verify "$stage/channel.json" installer-promote.yml "$promotion_source" \
            "$(run_field "$stage/channel.json" promotion_run_id)" "$(run_field "$stage/channel.json" promotion_run_attempt)"
        "$jq" -e --arg channel "$channel" '
            .schema == "elevenid.installer-channel/v1" and .repository == "ElevenID/marty-ui"
            and .channel == $channel and (.generation | type == "number" and . > 0 and floor == .)
            and (.admission_sha256 | test("^[0-9a-f]{64}$"))
            and (.issued_at | type == "number" and floor == .)
            and (.expires_at | type == "number" and floor == .)
            and .issued_at <= now and .expires_at > now
            and .expires_at > .issued_at and .expires_at - .issued_at <= 604800' "$stage/channel.json" >/dev/null
        version=$("$jq" -er '.release_tag' "$stage/channel.json")
        printf '%s\n' "$version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-nightly\.20[0-9]{6}\.[1-9][0-9]*)?$' || fail 'Invalid channel version'
        case "$channel:$version" in nightly:*-nightly.*|stable:v*) ;; *) fail 'Channel tier differs' ;; esac
        case "$channel:$version" in stable:*-nightly.*) fail 'Channel tier differs' ;; esac
    fi
    signed_download "$base/installer-admission-$version/installer-admission.json" "$stage/admission.json" 65536
    source=$("$jq" -er '.source_sha | select(test("^[0-9a-f]{40}$"))' "$stage/admission.json")
    promotion_source=$("$jq" -er '.promotion_source_sha | select(test("^[0-9a-f]{40}$"))' "$stage/admission.json")
    verify "$stage/admission.json" installer-promote.yml "$promotion_source" \
        "$(run_field "$stage/admission.json" promotion_run_id)" "$(run_field "$stage/admission.json" promotion_run_attempt)"
    "$jq" -e --arg tag "$version" --arg platform "$platform" '
        .schema == "elevenid.installer-admission/v1" and .repository == "ElevenID/marty-ui"
        and .release_tag == $tag and .platform == $platform and .status == "accepted"
        and (.operator_sha256 | test("^[0-9a-f]{64}$"))
        and (.inventory_sha256 | test("^[0-9a-f]{64}$"))' "$stage/admission.json" >/dev/null
    if [ -f "$stage/channel.json" ]; then
        [ "$(digest "$stage/admission.json")" = "$("$jq" -er '.admission_sha256' "$stage/channel.json")" ] || fail 'Channel admission changed during download'
        [ "$source" = "$("$jq" -er '.source_sha' "$stage/channel.json")" ] || fail 'Channel source differs'
    fi
    case "$version" in *-nightly.*) workflow=nightly-release.yml ;; *) workflow=cd.yml ;; esac
    signed_download "$base/$version/$operator_asset" "$stage/marty-deploy" 536870912
    [ "$(digest "$stage/marty-deploy")" = "$("$jq" -er '.operator_sha256' "$stage/admission.json")" ] || fail 'Operator digest differs from admitted version'
    verify "$stage/marty-deploy" "$workflow" "$source" \
        "$(run_field "$stage/admission.json" build_run_id)" "$(run_field "$stage/admission.json" build_run_attempt)"
    if [ -f "$stage/channel.json" ]; then
        recheck_channel_pointer
    fi
    chmod 700 "$stage/marty-deploy"
    [ "$("$stage/marty-deploy" --build-identity)" = "$source:$version" ] || fail 'Operator build identity differs'
    set -- install --version "$version" --verified-admission "$stage/admission.json" \
        --verification-tools "$stage" --gh-bin "$gh" \
        --docker-host "$docker_endpoint" --docker-engine-id "$docker_engine_id" --docker-bin "$docker_bin" \
        --runtime-profile rootless
    [ -z "$destination" ] || set -- "$@" --install-dir "$destination"
    [ -z "$foundation_file" ] || set -- "$@" --foundation-file "$foundation_file"
    [ -z "$hosting_file" ] || set -- "$@" --hosting-file "$hosting_file"
    [ -z "$acme_staging_roots" ] || set -- "$@" --acme-staging-roots "$acme_staging_roots"
    if [ -f "$stage/channel.json" ]; then
        set -- "$@" --channel "$channel" --verified-channel "$stage/channel.json"
    fi
    [ "$yes" = false ] || set -- "$@" --yes
    # Operator re-verifies admission/inventory and owns persistent state. Keep
    # staging alive until it exits; no exec, so the cleanup trap also runs.
    "$stage/marty-deploy" "$@"
)
main "$@" --bootstrap-complete
