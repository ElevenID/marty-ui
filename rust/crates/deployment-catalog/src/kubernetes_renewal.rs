//! Kubernetes transport around the existing Renewal AppRole and native producers.
//! Private intent precedes authority use; a candidate never changes live Secrets,
//! Deployments, the selected generation, remote key versions or either issuer.
use crate::generation;
use serde_json::{json, Value};

pub const RECOVERY: &str = "Kubernetes renewal requires operator recovery";
pub const MINIMUM_TTL: u64 = 3600;
pub const OPERATION_SECONDS: u64 = 900;
const BINDING_SCHEMA: &str = "marty.kubernetes-renewal-binding/v1";
const TLS_METADATA: &str = "selfhost-tls-kms-roles.json";
const IDENTITY_FILES: [&str; 3] = [
    "renewal-leaf-policies.json",
    "renewal-role-id",
    "renewal-secret-id",
];

/// Compiled public names and limits only. This function performs no I/O.
pub fn metadata() -> Value {
    let (tls, keycloak, tokens) = generation::inventories();
    let renewable = tls.union(&keycloak).cloned().collect::<Vec<_>>();
    assert_eq!((renewable.len(), tokens.len()), (40, 21));
    json!({
        "schema":"marty.kubernetes-renewal/v1",
        "enrollmentOperation":"kubernetes-renewal-enroll",
        "stagingOperation":"kubernetes-renewal-stage",
        "bindingSchema":BINDING_SCHEMA,
        "identityFiles":IDENTITY_FILES,
        "minimumTtlSeconds":MINIMUM_TTL,
        "operationBudgetSeconds":OPERATION_SECONDS,
        "renewableFiles":renewable,
        "unchangedFiles":["workload_identity_ca_cert"],
        "changedFiles":39,
        "scopedLeafTokens":21,
        "tlsMetadataFile":TLS_METADATA,
    })
}

#[cfg(target_os = "linux")]
pub use runtime::{enroll, stage, verify_candidate};

#[cfg(not(target_os = "linux"))]
pub async fn enroll(
    _endpoint: &str,
    _ca: &std::path::Path,
    _identity: &std::path::Path,
    _context: &Value,
) -> crate::operator::Result<Value> {
    Err(crate::operator::REFUSAL)
}

#[cfg(not(target_os = "linux"))]
pub async fn stage(
    _endpoint: &str,
    _ca: &std::path::Path,
    _identity: &std::path::Path,
    _context: &Value,
) -> crate::operator::Result<Value> {
    Err(crate::operator::REFUSAL)
}

#[cfg(not(target_os = "linux"))]
pub async fn verify_candidate(
    _endpoint: &str,
    _ca: &std::path::Path,
    _identity: &std::path::Path,
    _context: &Value,
) -> crate::operator::Result<Value> {
    Err(crate::operator::REFUSAL)
}

#[cfg(target_os = "linux")]
mod runtime {
    use super::*;
    use crate::{
        activation_preflight,
        application_authority::Binding,
        approle::{self, Role},
        keycloak_provision,
        kubernetes_application::{owned_directory, read_owned_file, snapshot, Snapshot},
        operator::{Result, REFUSAL},
        operator_files::{finish_generation, generation_output},
        operator_http, operator_process,
    };
    use async_trait::async_trait;
    use marty_openbao_http::OpenBaoHttp;
    use reqwest::Method;
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs::{self, File, OpenOptions},
        future::Future,
        os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
        path::{Path, PathBuf},
        time::{Duration, Instant},
    };

    const EXECUTABLE: &str = "/usr/local/bin/marty-passport-tls-bootstrap";
    const ENROLLMENT_SCHEMA: &str = "marty.kubernetes-renewal-enrollment/v1";
    const STAGING_SCHEMA: &str = "marty.kubernetes-renewal-staging/v1";
    const MAX_RECEIPT: usize = 65536;
    // The outer activation includes Pod setup, all publications, rollout,
    // delivery and selection under one 900-second deadline. Its fresh proof
    // must retain the public one-hour floor after that entire remaining window,
    // even when the native verification has a shorter execution budget.
    const ACTIVATION_PROOF_TTL: u64 = MINIMUM_TTL + OPERATION_SECONDS;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Enrollment {
        root_token: String,
        current: PathBuf,
        output: PathBuf,
        binding: Binding,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Staging {
        current: PathBuf,
        candidate: PathBuf,
        output: PathBuf,
        binding_file: PathBuf,
        binding: Binding,
        budget_seconds: u64,
    }

    #[derive(Deserialize, Serialize, PartialEq, Eq)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct BindingReceipt {
        schema: String,
        binding: Binding,
        producer_nonce: String,
    }

    fn require(condition: bool) -> Result<()> {
        if condition {
            Ok(())
        } else {
            Err(REFUSAL)
        }
    }

    fn nonce(binding: &Binding) -> Result<&str> {
        binding.validate()?;
        binding
            .workload_project
            .strip_prefix("marty-selfhost-disposable-k8s-")
            .ok_or(REFUSAL)
    }

    fn safe_token(value: &str) -> Result<()> {
        require(
            (20..=1024).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_graphic()),
        )
    }

    fn input(path: &Path, maximum: usize) -> Result<Vec<u8>> {
        require(path.is_absolute() && path.canonicalize().map_err(|_| REFUSAL)? == path)?;
        let (bytes, _) = read_owned_file(path, maximum, &[0o400, 0o600])?;
        require(!bytes.is_empty())?;
        Ok(bytes)
    }

    /// Pin every directory identity as well as comparing its byte/mode snapshot.
    /// A rename-and-recreate cannot pass merely by copying the same bytes back.
    struct HeldDirectory {
        path: PathBuf,
        file: File,
    }

    impl HeldDirectory {
        fn open(path: &Path, empty: bool) -> Result<Self> {
            let path = owned_directory(path)?;
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(&path)
                .map_err(|_| REFUSAL)?;
            let held = Self { path, file };
            held.require()?;
            if empty {
                require(
                    fs::read_dir(&held.path)
                        .map_err(|_| REFUSAL)?
                        .next()
                        .is_none(),
                )?;
            }
            Ok(held)
        }

        fn require(&self) -> Result<()> {
            owned_directory(&self.path)?;
            let now = fs::symlink_metadata(&self.path).map_err(|_| REFUSAL)?;
            let old = self.file.metadata().map_err(|_| REFUSAL)?;
            require(
                (now.dev(), now.ino(), now.uid(), now.gid(), now.mode())
                    == (old.dev(), old.ino(), old.uid(), old.gid(), old.mode()),
            )
        }

        fn sync(&self) -> Result<()> {
            self.require()?;
            self.file.sync_all().map_err(|_| REFUSAL)
        }

        fn child(&self, name: &str) -> Result<Self> {
            self.require()?;
            let path = self.path.join(name);
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .map_err(|_| REFUSAL)?;
            self.sync()?;
            Self::open(&path, true)
        }
    }

    fn distinct(directories: &[&HeldDirectory]) -> Result<()> {
        for (index, left) in directories.iter().enumerate() {
            for right in directories.iter().skip(index + 1) {
                require(
                    !left.path.starts_with(&right.path) && !right.path.starts_with(&left.path),
                )?;
            }
        }
        Ok(())
    }

    fn write(directory: &HeldDirectory, name: &str, bytes: &[u8], bound: usize) -> Result<()> {
        directory.require()?;
        require(
            !bytes.is_empty()
                && bytes.len() <= bound
                && !bytes.contains(&0)
                && !bytes.windows(11).any(|part| part == b"PRIVATE KEY")
                && !name.contains(['/', '\\'])
                && ![".", ".."].contains(&name),
        )?;
        let mut file = generation_output(&directory.path.join(name))?;
        // Retain even a partial exclusive write as uncertainty evidence.
        directory.sync()?;
        finish_generation(&mut file, bytes, 0o600)?;
        directory.sync()
    }

    fn receipt(directory: &HeldDirectory, name: &str, value: &Value, bound: usize) -> Result<()> {
        write(
            directory,
            name,
            &serde_json::to_vec(value).map_err(|_| REFUSAL)?,
            bound,
        )
    }

    fn terminal_receipt(directory: &HeldDirectory, value: &Value, budget: &Budget) -> Result<()> {
        directory.require()?;
        let bytes = serde_json::to_vec(value).map_err(|_| REFUSAL)?;
        require(!bytes.is_empty() && bytes.len() <= 4096)?;
        let path = directory.path.join("completed.json");
        let mut file = generation_output(&path)?;
        let created = file.metadata().map_err(|_| REFUSAL)?;
        let result = (|| {
            directory.sync()?;
            finish_generation(&mut file, &bytes, 0o600)?;
            directory.sync()?;
            budget.remaining(true)?;
            Ok(())
        })();
        if result.is_err() {
            // Remove only our own exclusive terminal artifact. Keep the intent,
            // issued leaves and all other recovery evidence on every failure.
            if fs::symlink_metadata(&path)
                .is_ok_and(|now| (now.dev(), now.ino()) == (created.dev(), created.ino()))
            {
                let _ = fs::remove_file(path);
                let _ = directory.sync();
            }
        }
        result
    }

    fn hashes(values: &Snapshot) -> BTreeMap<String, Value> {
        values
            .iter()
            .map(|(name, (bytes, mode))| {
                (
                    name.clone(),
                    json!({"sha256":format!("{:x}",Sha256::digest(bytes)),"mode":mode}),
                )
            })
            .collect()
    }

    fn policies(bytes: &[u8]) -> Result<Vec<String>> {
        let names: Vec<String> = serde_json::from_slice(bytes).map_err(|_| REFUSAL)?;
        require(
            names.len() == 21
                && names.windows(2).all(|pair| pair[0] < pair[1])
                && names.iter().all(|name| {
                    !name.is_empty()
                        && name.len() <= 160
                        && !name.starts_with("installer-ingress-")
                        && !["root", "default", "selfhost-kms-renewal"].contains(&name.as_str())
                        && name.bytes().all(|byte| {
                            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                        })
                }),
        )?;
        Ok(names)
    }

    fn identity_snapshot(directory: &HeldDirectory) -> Result<Snapshot> {
        directory.require()?;
        let values = snapshot(&directory.path)?;
        require(values.keys().map(String::as_str).eq(IDENTITY_FILES))?;
        for (name, (bytes, mode)) in &values {
            require([0o400, 0o600].contains(mode))?;
            if name == "renewal-leaf-policies.json" {
                require(bytes.len() <= 4096)?;
                policies(bytes)?;
            } else {
                require(bytes.len() <= 513)?;
                let token = bytes.strip_suffix(b"\n").unwrap_or(bytes);
                safe_token(std::str::from_utf8(token).map_err(|_| REFUSAL)?)?;
            }
        }
        directory.require()?;
        Ok(values)
    }

    fn same_policies(mut observed: Vec<String>, expected: &[String]) -> Result<()> {
        observed.sort_unstable();
        require(observed == expected)
    }

    fn binding_receipt(bytes: &[u8], expected: &Binding) -> Result<BindingReceipt> {
        let receipt: BindingReceipt = serde_json::from_slice(bytes).map_err(|_| REFUSAL)?;
        require(
            receipt.schema == BINDING_SCHEMA
                && receipt.binding == *expected
                && receipt.producer_nonce == nonce(expected)?,
        )?;
        Ok(receipt)
    }

    struct Budget {
        deadline: Instant,
        work_deadline: Instant,
    }

    impl Budget {
        fn new(seconds: u64) -> Result<Self> {
            require((60..=OPERATION_SECONDS).contains(&seconds))?;
            let deadline = Instant::now() + Duration::from_secs(seconds);
            Ok(Self {
                deadline,
                work_deadline: deadline - Duration::from_secs(40),
            })
        }

        fn remaining(&self, cleanup: bool) -> Result<Duration> {
            let deadline = if cleanup {
                self.deadline
            } else {
                self.work_deadline
            };
            deadline
                .checked_duration_since(Instant::now())
                .filter(|remaining| !remaining.is_zero())
                .ok_or(RECOVERY)
        }

        async fn run<T>(&self, cleanup: bool, work: impl Future<Output = Result<T>>) -> Result<T> {
            let remaining = self.remaining(cleanup)?;
            tokio::time::timeout(remaining, work)
                .await
                .map_err(|_| RECOVERY)?
        }

        fn verification_ttl(&self) -> Result<u64> {
            // The earliest live proof must remain valid through all later
            // checks, session retirement and final durable completion.
            Ok(MINIMUM_TTL + self.remaining(true)?.as_secs() + 1)
        }
    }

    fn workload_environment(
        endpoint: &str,
        ca: &Path,
        output: &Path,
        binding: &Binding,
    ) -> BTreeMap<String, String> {
        [
            ("PATH", "/usr/local/bin:/usr/bin:/bin".into()),
            ("HOME", output.to_string_lossy().into_owned()),
            ("LANG", "C".into()),
            ("BAO_ADDR", endpoint.into()),
            ("BAO_CACERT", ca.to_string_lossy().into_owned()),
            (
                "BAO_RENEWAL_TOKEN_FILE",
                output
                    .join("authority.token")
                    .to_string_lossy()
                    .into_owned(),
            ),
            ("MARTY_TLS_BOOTSTRAP_PROFILE", "selfhost-renew".into()),
            ("MARTY_SELFHOST_WORKLOAD_PKI_MOUNT", "workload-pki".into()),
            ("MARTY_SELFHOST_PROJECT", binding.workload_project.clone()),
            (
                "SELFHOST_TLS_OUTPUT_DIR",
                output.join("tls").to_string_lossy().into_owned(),
            ),
        ]
        .into_iter()
        .map(|(key, value)| (key.into(), value))
        .collect()
    }

    // This seam tests lifecycle failures without substituting a second issuer
    // or policy engine. Production always uses the existing native owners.
    #[async_trait]
    trait Producers: Sync {
        async fn health(&self, binding: &Binding) -> Result<()>;
        async fn inventory(&self, token: &str, current: &Path) -> Result<Vec<String>>;
        async fn enroll(&self, identity: &Path, context: &Value) -> Result<()>;
        async fn login(&self, identity: &Path, captured: &mut Option<String>) -> Result<Value>;
        async fn authority(&self, token: &str) -> Result<()>;
        fn executable(&self) -> Result<()>;
        fn tls(&self, output: &Path, binding: &Binding, remaining: Duration) -> Result<()>;
        async fn keycloak(&self, token: &str, nonce: &str) -> Result<Value>;
        async fn tokens(&self, checks: &Value) -> Result<Vec<String>>;
        async fn certificates(&self, checks: &Value) -> Result<()>;
        async fn retire(&self, token: &str) -> Result<()>;
    }

    struct Native<'a> {
        bao: &'a OpenBaoHttp,
        ca: &'a Path,
    }

    #[async_trait]
    impl Producers for Native<'_> {
        async fn health(&self, binding: &Binding) -> Result<()> {
            let observed =
                operator_http::request(self.bao, Method::GET, "sys/health", None, None).await?;
            require(
                observed["initialized"] == true
                    && observed["sealed"] == false
                    && observed["standby"] == false
                    && observed["cluster_id"] == binding.openbao_cluster_id,
            )
        }

        async fn inventory(&self, token: &str, current: &Path) -> Result<Vec<String>> {
            activation_preflight::renewal_inventory(
                self.bao,
                &json!({"token":token,"current":current}),
            )
            .await
        }

        async fn enroll(&self, identity: &Path, context: &Value) -> Result<()> {
            approle::bootstrap(self.bao, Role::Renewal, identity, context).await
        }

        async fn login(&self, identity: &Path, captured: &mut Option<String>) -> Result<Value> {
            approle::renewal_login_captured(self.bao, identity, captured).await
        }

        async fn authority(&self, token: &str) -> Result<()> {
            activation_preflight::authority(self.bao, token, false).await?;
            let lookup = operator_http::request(
                self.bao,
                Method::POST,
                "auth/token/lookup",
                Some(&json!({"token":token})),
                Some(token),
            )
            .await?;
            let data = &lookup["data"];
            require(
                data["type"] == "service"
                    && data["num_uses"] == 0
                    && data["orphan"] == true
                    && data
                        .get("identity_policies")
                        .is_none_or(|value| value.is_null() || value == &json!([]))
                    && data
                        .get("period")
                        .is_none_or(|value| value.is_null() || value == 0),
            )
        }

        fn executable(&self) -> Result<()> {
            operator_process::workload_executable().map_err(|_| REFUSAL)
        }

        fn tls(&self, output: &Path, binding: &Binding, remaining: Duration) -> Result<()> {
            operator_process::run_child(
                Path::new(EXECUTABLE),
                &workload_environment(self.bao.origin(), self.ca, output, binding),
                output,
                remaining.min(Duration::from_secs(600)),
            )
            .map_err(|_| RECOVERY)
        }

        async fn keycloak(&self, token: &str, nonce: &str) -> Result<Value> {
            keycloak_provision::provision(
                self.bao,
                &json!({"token":token,"renew":true,"pki_mount":"keycloak-pki","nonce":nonce}),
            )
            .await
        }

        async fn tokens(&self, checks: &Value) -> Result<Vec<String>> {
            activation_preflight::tokens(self.bao, checks).await
        }

        async fn certificates(&self, checks: &Value) -> Result<()> {
            activation_preflight::certificates(self.bao, checks).await
        }

        async fn retire(&self, token: &str) -> Result<()> {
            operator_process::retire(self.bao, token)
                .await
                .map_err(|_| RECOVERY)
        }
    }

    pub async fn enroll(
        endpoint: &str,
        ca: &Path,
        identity: &Path,
        context: &Value,
    ) -> Result<Value> {
        // Validate the file before the shared HTTPS client opens it.
        let ca_bytes = input(ca, 65536)?;
        let context: Enrollment = serde_json::from_value(context.clone()).map_err(|_| REFUSAL)?;
        let bao = OpenBaoHttp::connect(endpoint, Some(ca), Duration::from_secs(10))
            .map_err(|_| REFUSAL)?;
        require(input(ca, 65536)? == ca_bytes)?;
        enroll_with(&Native { bao: &bao, ca }, ca, &ca_bytes, identity, context).await
    }

    async fn enroll_with(
        api: &impl Producers,
        ca: &Path,
        ca_bytes: &[u8],
        identity: &Path,
        context: Enrollment,
    ) -> Result<Value> {
        let nonce = nonce(&context.binding)?.to_owned();
        safe_token(&context.root_token)?;
        let identity = HeldDirectory::open(identity, true)?;
        let current = HeldDirectory::open(&context.current, false)?;
        let output = HeldDirectory::open(&context.output, true)?;
        distinct(&[&identity, &current, &output])?;
        let before = snapshot(&current.path)?;
        require(
            before
                .get("openbao_tls_ca_cert")
                .is_some_and(|entry| entry.0 == ca_bytes),
        )?;
        let budget = Budget::new(OPERATION_SECONDS)?;
        budget.run(false, api.health(&context.binding)).await?;
        let mut names = budget
            .run(false, api.inventory(&context.root_token, &current.path))
            .await?;
        names.sort_unstable();
        policies(&serde_json::to_vec(&names).map_err(|_| REFUSAL)?)?;
        current.require()?;
        require(snapshot(&current.path)? == before && input(ca, 65536)? == ca_bytes)?;
        budget.run(false, api.health(&context.binding)).await?;
        receipt(
            &output,
            "pending.json",
            &json!({
                "schema":"marty.kubernetes-renewal-enrollment-intent/v1",
                "binding":context.binding,"producerNonce":nonce,"inputHashes":hashes(&before),
                "activated":false,
            }),
            MAX_RECEIPT,
        )?;
        // A failed/unknown bootstrap response leaves this durable intent. The
        // generic owner retains its existing rollback; this adapter never retries.
        let result: Result<Value> = async {
            budget.run(false, api.enroll(&identity.path, &json!({
                "root_token":context.root_token,"names":names,"allow_secret_id_rotation":false,
            }))).await?;
            let credentials = identity_snapshot(&identity)?;
            same_policies(policies(&credentials["renewal-leaf-policies.json"].0)?, &names)?;
            current.require()?;
            require(snapshot(&current.path)? == before && input(ca, 65536)? == ca_bytes)?;
            budget.run(false, api.health(&context.binding)).await?;
            let bound = BindingReceipt { schema:BINDING_SCHEMA.into(), binding:context.binding.clone(), producer_nonce:nonce.clone() };
            receipt(&output, "binding.json", &serde_json::to_value(bound).map_err(|_| REFUSAL)?, 4096)?;
            identity.sync()?;
            budget.remaining(true)?;
            terminal_receipt(&output, &json!({
                "schema":ENROLLMENT_SCHEMA,"binding":context.binding,"producerNonce":nonce,
                "identityFiles":IDENTITY_FILES,"scopedLeafTokens":21,"enrolled":true,"activated":false,
            }), &budget)?;
            Ok(json!({"ready":true,"identity":identity.path,"binding":output.path.join("binding.json"),"count":3}))
        }.await;
        result.map_err(|_| RECOVERY)
    }

    pub async fn stage(
        endpoint: &str,
        ca: &Path,
        identity: &Path,
        context: &Value,
    ) -> Result<Value> {
        let ca_bytes = input(ca, 65536)?;
        let context: Staging = serde_json::from_value(context.clone()).map_err(|_| REFUSAL)?;
        let bao = OpenBaoHttp::connect(endpoint, Some(ca), Duration::from_secs(10))
            .map_err(|_| REFUSAL)?;
        require(input(ca, 65536)? == ca_bytes)?;
        stage_with(&Native { bao: &bao, ca }, ca, &ca_bytes, identity, context).await
    }

    /// Revalidate an existing candidate under a fresh scoped Renewal session.
    /// The verifier never calls either producer or creates credentials.
    pub async fn verify_candidate(
        endpoint: &str,
        ca: &Path,
        identity: &Path,
        context: &Value,
    ) -> Result<Value> {
        let ca_bytes = input(ca, 65536)?;
        let context: Staging = serde_json::from_value(context.clone()).map_err(|_| REFUSAL)?;
        let bao = OpenBaoHttp::connect(endpoint, Some(ca), Duration::from_secs(10))
            .map_err(|_| REFUSAL)?;
        require(input(ca, 65536)? == ca_bytes)?;
        verify_with(&Native { bao: &bao, ca }, ca, &ca_bytes, identity, context).await
    }

    async fn verify_with(
        api: &impl Producers,
        ca: &Path,
        ca_bytes: &[u8],
        identity: &Path,
        context: Staging,
    ) -> Result<Value> {
        let budget = Budget::new(context.budget_seconds)?;
        let nonce = nonce(&context.binding)?.to_owned();
        let identity = HeldDirectory::open(identity, false)?;
        let current = HeldDirectory::open(&context.current, false)?;
        let output = HeldDirectory::open(&context.output, true)?;
        let candidate = HeldDirectory::open(&context.candidate, false)?;
        distinct(&[&identity, &current, &output, &candidate])?;
        let (before, next) = crate::kubernetes_renewal_activation::qualify_generation(
            &current.path,
            &candidate.path,
        )?;
        require(
            before
                .get("openbao_tls_ca_cert")
                .is_some_and(|entry| entry.0 == ca_bytes),
        )?;
        let credentials = identity_snapshot(&identity)?;
        let enrolled = policies(&credentials["renewal-leaf-policies.json"].0)?;
        let bound_bytes = input(&context.binding_file, 4096)?;
        binding_receipt(&bound_bytes, &context.binding)?;
        let unchanged = || -> Result<()> {
            for directory in [&current, &identity, &output, &candidate] {
                directory.require()?;
            }
            require(
                snapshot(&current.path)? == before
                    && snapshot(&candidate.path)? == next
                    && identity_snapshot(&identity)? == credentials
                    && input(&context.binding_file, 4096)? == bound_bytes
                    && input(ca, 65536)? == ca_bytes,
            )
        };
        budget.run(false, api.health(&context.binding)).await?;
        unchanged()?;
        receipt(
            &output,
            "pending.json",
            &json!({
                "schema":"marty.kubernetes-renewal-verification-intent/v1", "binding":context.binding,
                "producerNonce":nonce,"inputHashes":hashes(&before),"candidateHashes":hashes(&next),
                "identityHashes":hashes(&credentials),
                "bindingSha256":format!("{:x}",Sha256::digest(&bound_bytes)),
                "budgetSeconds":context.budget_seconds,"activated":false,
            }),
            MAX_RECEIPT,
        )?;
        let mut captured = None;
        let login = budget
            .run(false, api.login(&identity.path, &mut captured))
            .await;
        let Some(token) = captured else {
            return Err(RECOVERY);
        };
        let custody = write(&output, "authority.token", token.as_bytes(), 1024);
        let verified: Result<()> = async {
            custody?;
            safe_token(&token)?;
            require(login?["token"] == token)?;
            unchanged()?;
            budget.run(false, api.health(&context.binding)).await?;
            budget.run(false, api.authority(&token)).await?;
            require(!next.values().any(|entry| entry.0.windows(token.len()).any(|part| part == token.as_bytes())))?;
            let checks = json!({"token":token,"old":current.path,"new":candidate.path,
                "minimum_ttl":ACTIVATION_PROOF_TTL,"require_orphan_new":true,"require_orphan_old":false,
                "require_closed_new_metadata":true,"replacement":null,"retiring":false});
            same_policies(budget.run(false, api.tokens(&checks)).await?, &enrolled)?;
            budget.run(false, api.certificates(&checks)).await?;
            budget.run(false, api.health(&context.binding)).await?;
            unchanged()?;
            receipt(&output, "validated.json", &json!({
                "schema":"marty.kubernetes-renewal-verification-validation/v1","binding":context.binding,
                "inputHashes":hashes(&before),"outputHashes":hashes(&next),"files":next.len(),"changedFiles":39,
                "scopedLeafTokens":21,"remoteKeyVersion":1,"caChanged":false,"minimumTtlSeconds":MINIMUM_TTL,
            }), MAX_RECEIPT)
        }.await;
        // A returned session has one cleanup owner even after malformed login,
        // private write, scope, token, certificate or custody-check failure.
        budget
            .run(true, api.retire(&token))
            .await
            .map_err(|_| RECOVERY)?;
        receipt(
            &output,
            "session-retired.json",
            &json!({
                "schema":"marty.kubernetes-renewal-session-retirement/v1","transientRevoked":true,
            }),
            4096,
        )
        .map_err(|_| RECOVERY)?;
        let finish: Result<Value> = (|| {
            verified?;
            unchanged()?;
            let found = fs::read_dir(&output.path)
                .map_err(|_| REFUSAL)?
                .map(|entry| {
                    entry
                        .map_err(|_| REFUSAL)?
                        .file_name()
                        .into_string()
                        .map_err(|_| REFUSAL)
                })
                .collect::<Result<BTreeSet<_>>>()?;
            require(
                found
                    == [
                        "pending.json",
                        "authority.token",
                        "validated.json",
                        "session-retired.json",
                    ]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
            )?;
            budget.remaining(true)?;
            terminal_receipt(
                &output,
                &json!({
                    "schema":"marty.kubernetes-renewal-verification/v1","binding":context.binding,"producerNonce":nonce,
                    "files":next.len(),"changedFiles":39,"scopedLeafTokens":21,"transientRevoked":true,
                    "activated":false,"caChanged":false,"minimumTtlSeconds":MINIMUM_TTL,
                }),
                &budget,
            )?;
            Ok(json!({"ready":true,"count":39,"minimumTtlSeconds":MINIMUM_TTL}))
        })();
        finish.map_err(|_| RECOVERY)
    }

    async fn stage_with(
        api: &impl Producers,
        ca: &Path,
        ca_bytes: &[u8],
        identity: &Path,
        context: Staging,
    ) -> Result<Value> {
        let budget = Budget::new(context.budget_seconds)?;
        let nonce = nonce(&context.binding)?.to_owned();
        let identity = HeldDirectory::open(identity, false)?;
        let current = HeldDirectory::open(&context.current, false)?;
        let output = HeldDirectory::open(&context.output, true)?;
        let candidate = HeldDirectory::open(&context.candidate, true)?;
        distinct(&[&identity, &current, &output, &candidate])?;
        let before = snapshot(&current.path)?;
        require(
            before
                .get("openbao_tls_ca_cert")
                .is_some_and(|entry| entry.0 == ca_bytes),
        )?;
        let credentials = identity_snapshot(&identity)?;
        let enrolled = policies(&credentials["renewal-leaf-policies.json"].0)?;
        let bound_bytes = input(&context.binding_file, 4096)?;
        binding_receipt(&bound_bytes, &context.binding)?;
        api.executable()?;
        let unchanged = || -> Result<()> {
            for directory in [&current, &identity, &output, &candidate] {
                directory.require()?;
            }
            require(
                snapshot(&current.path)? == before
                    && identity_snapshot(&identity)? == credentials
                    && input(&context.binding_file, 4096)? == bound_bytes
                    && input(ca, 65536)? == ca_bytes,
            )
        };
        budget.run(false, api.health(&context.binding)).await?;
        unchanged()?;
        receipt(
            &output,
            "pending.json",
            &json!({
                "schema":"marty.kubernetes-renewal-staging-intent/v1","binding":context.binding,
                "producerNonce":nonce,"inputHashes":hashes(&before),"identityHashes":hashes(&credentials),
                "bindingSha256":format!("{:x}",Sha256::digest(&bound_bytes)),
                "budgetSeconds":context.budget_seconds,"activated":false,
            }),
            MAX_RECEIPT,
        )?;
        let mut captured = None;
        let login = budget
            .run(false, api.login(&identity.path, &mut captured))
            .await;
        let Some(token) = captured else {
            // A missing login response cannot establish that no session exists.
            return Err(RECOVERY);
        };
        let custody = write(&output, "authority.token", token.as_bytes(), 1024);
        let produced: Result<Snapshot> = async {
            custody?;
            safe_token(&token)?;
            let login = login?;
            require(login["token"] == token)?;
            unchanged()?;
            budget.run(false, api.health(&context.binding)).await?;
            budget.run(false, api.authority(&token)).await?;
            same_policies(budget.run(false, api.inventory(&token, &current.path)).await?, &enrolled)?;
            unchanged()?;
            let tls = output.child("tls")?;
            let keycloak = output.child("keycloak")?;
            api.tls(&output.path, &context.binding, budget.remaining(false)?)?;
            budget.remaining(false)?;
            let values = budget.run(false, api.keycloak(&token, &nonce)).await?;
            let values = values.as_object().ok_or(REFUSAL)?;
            let (tls_names, keycloak_names, token_names) = generation::inventories();
            require(values.keys().cloned().collect::<BTreeSet<_>>() == keycloak_names)?;
            for (name, value) in values {
                let value = value.as_str().ok_or(REFUSAL)?;
                if token_names.contains(name) { safe_token(value)?; }
                write(&keycloak, name, value.as_bytes(), if token_names.contains(name) {1024} else {65536})?;
            }
            tls.require()?;
            keycloak.require()?;
            let produced_tls = snapshot(&tls.path)?;
            let produced_keycloak = snapshot(&keycloak.path)?;
            let expected_tls = tls_names.into_iter().chain([TLS_METADATA.into()]).collect::<BTreeSet<_>>();
            require(produced_tls.keys().cloned().collect::<BTreeSet<_>>() == expected_tls
                && produced_keycloak.keys().cloned().collect::<BTreeSet<_>>() == keycloak_names
                && produced_tls.values().chain(produced_keycloak.values()).all(|entry| entry.1 == 0o600))?;
            require(produced_tls[TLS_METADATA].0.len() <= 8192)?;
            for name in token_names {
                let value = produced_tls.get(&name).or_else(|| produced_keycloak.get(&name)).ok_or(REFUSAL)?;
                require(value.0.len() <= 1025)?;
                safe_token(std::str::from_utf8(value.0.strip_suffix(b"\n").unwrap_or(&value.0)).map_err(|_| REFUSAL)?)?;
            }
            unchanged()?;
            require(generation::stage(&current.path, &tls.path, &keycloak.path, &candidate.path, false)? == before.len())?;
            require(generation::verify(&current.path, &candidate.path, false, false)? == (before.len(), 39))?;
            let next = snapshot(&candidate.path)?;
            require(!next.values().any(|entry| entry.0.windows(token.len()).any(|part| part == token.as_bytes())))?;
            let checks = json!({"token":token,"old":current.path,"new":candidate.path,
                "minimum_ttl":budget.verification_ttl()?,"require_orphan_new":true,"require_orphan_old":false,
                "require_closed_new_metadata":true,
                "replacement":null,"retiring":false});
            same_policies(budget.run(false, api.tokens(&checks)).await?, &enrolled)?;
            budget.run(false, api.certificates(&checks)).await?;
            budget.run(false, api.health(&context.binding)).await?;
            unchanged()?;
            require(snapshot(&candidate.path)? == next)?;
            for directory in [&tls, &keycloak, &candidate] { directory.sync()?; }
            receipt(&output, "validated.json", &json!({
                "schema":"marty.kubernetes-renewal-validation/v1","binding":context.binding,
                "outputHashes":hashes(&next),"files":next.len(),"changedFiles":39,
                "scopedLeafTokens":21,"remoteKeyVersion":1,"caChanged":false,
                "minimumTtlSeconds":MINIMUM_TTL,
            }), MAX_RECEIPT)?;
            Ok(next)
        }.await;
        // Every known session reaches this owner, including malformed login
        // metadata, failed authority qualification, producer and storage errors.
        budget
            .run(true, api.retire(&token))
            .await
            .map_err(|_| RECOVERY)?;
        receipt(
            &output,
            "session-retired.json",
            &json!({
                "schema":"marty.kubernetes-renewal-session-retirement/v1","transientRevoked":true,
            }),
            4096,
        )
        .map_err(|_| RECOVERY)?;
        let finish: Result<Value> = (|| {
            let next = produced?;
            unchanged()?;
            require(snapshot(&candidate.path)? == next)?;
            let expected = [
                "pending.json",
                "authority.token",
                "tls",
                "keycloak",
                "validated.json",
                "session-retired.json",
            ];
            let found = fs::read_dir(&output.path)
                .map_err(|_| REFUSAL)?
                .map(|entry| {
                    entry
                        .map_err(|_| REFUSAL)?
                        .file_name()
                        .into_string()
                        .map_err(|_| REFUSAL)
                })
                .collect::<Result<BTreeSet<_>>>()?;
            require(found == expected.into_iter().map(str::to_owned).collect())?;
            budget.remaining(true)?;
            candidate.sync()?;
            terminal_receipt(
                &output,
                &json!({
                    "schema":STAGING_SCHEMA,"binding":context.binding,"producerNonce":nonce,
                    "files":next.len(),"changedFiles":39,"scopedLeafTokens":21,
                    "transientRevoked":true,"activated":false,"caChanged":false,
                }),
                &budget,
            )?;
            Ok(
                json!({"ready":true,"candidate":candidate.path,"count":next.len(),"changed":39,"transientRevoked":true}),
            )
        })();
        finish.map_err(|_| RECOVERY)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{
            os::unix::fs::{symlink, PermissionsExt},
            sync::Mutex,
        };

        const LOGIN_TOKEN: &str = "synthetic-known-renewal-session-token";
        const CA: &[u8] = b"synthetic-openbao-public-ca";
        const WORKLOAD_CA: &[u8] = b"synthetic-unchanged-workload-ca";

        fn binding() -> Binding {
            Binding {
                namespace: "renewal-test".into(),
                namespace_uid: "11111111-2222-3333-4444-555555555555".into(),
                openbao_cluster_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into(),
                workload_project: "marty-selfhost-disposable-k8s-123456abcdef".into(),
            }
        }

        fn names() -> Vec<String> {
            (0..21)
                .map(|index| format!("scoped-leaf-{index:02}"))
                .collect()
        }

        fn put(path: &Path, bytes: &[u8], mode: u32) {
            if path.exists() {
                // The owned fault injector may change its own read-only fixture;
                // production custody must detect the restored mode and new bytes.
                fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
            }
            fs::write(path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        }

        fn identity_files(path: &Path) {
            put(
                &path.join(IDENTITY_FILES[0]),
                &serde_json::to_vec(&names()).unwrap(),
                0o600,
            );
            for name in &IDENTITY_FILES[1..] {
                put(
                    &path.join(name),
                    format!("synthetic-private-{name}").as_bytes(),
                    0o600,
                );
            }
        }

        struct Fixture {
            _root: tempfile::TempDir,
            current: PathBuf,
            identity: PathBuf,
            output: PathBuf,
            candidate: PathBuf,
            ca: PathBuf,
            bound: PathBuf,
        }

        impl Fixture {
            fn new() -> Self {
                let root = tempfile::tempdir().unwrap();
                fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
                let child = |name| {
                    let path = root.path().join(name);
                    fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
                    path
                };
                let current = child("current");
                let identity = child("identity");
                let output = child("output");
                let candidate = child("candidate");
                let (tls, keycloak, _) = generation::inventories();
                for (index, name) in tls.union(&keycloak).enumerate() {
                    put(
                        &current.join(name),
                        format!("old-credential-{name}").as_bytes(),
                        [0o400, 0o440, 0o444, 0o600, 0o640, 0o644][index % 6],
                    );
                }
                put(
                    &current.join("workload_identity_ca_cert"),
                    WORKLOAD_CA,
                    0o444,
                );
                put(&current.join("openbao_tls_ca_cert"), CA, 0o444);
                // Whole-generation custody includes ordinary and empty extras.
                put(
                    &current.join("ordinary_token"),
                    b"ordinary-token-selected-after-activation",
                    0o440,
                );
                put(&current.join("unrelated_empty"), b"", 0o400);
                let ca = root.path().join("ca.crt");
                put(&ca, CA, 0o600);
                let bound = root.path().join("binding.json");
                put(
                    &bound,
                    &serde_json::to_vec(&json!({"schema":BINDING_SCHEMA,
                    "binding":binding(),"producerNonce":"123456abcdef"}))
                    .unwrap(),
                    0o600,
                );
                identity_files(&identity);
                Self {
                    _root: root,
                    current,
                    identity,
                    output,
                    candidate,
                    ca,
                    bound,
                }
            }

            fn staging(&self) -> Staging {
                Staging {
                    current: self.current.clone(),
                    candidate: self.candidate.clone(),
                    output: self.output.clone(),
                    binding_file: self.bound.clone(),
                    binding: binding(),
                    budget_seconds: 900,
                }
            }

            fn verification(&self) -> Staging {
                let (tls, keycloak, _) = generation::inventories();
                for (name, (bytes, mode)) in snapshot(&self.current).unwrap() {
                    let bytes = if name != "workload_identity_ca_cert"
                        && (tls.contains(&name) || keycloak.contains(&name))
                    {
                        format!("new-credential-{name}").into_bytes()
                    } else {
                        bytes
                    };
                    put(&self.candidate.join(name), &bytes, mode);
                }
                let mut context = self.staging();
                context.budget_seconds = 600;
                context
            }

            fn fake(&self, failure: &'static str) -> Fake {
                Fake {
                    failure,
                    certificate_ttl: None,
                    events: Mutex::new(Vec::new()),
                    current: self.current.clone(),
                    identity: self.identity.clone(),
                    output: self.output.clone(),
                    candidate: self.candidate.clone(),
                    bound: self.bound.clone(),
                }
            }
        }

        struct Fake {
            failure: &'static str,
            certificate_ttl: Option<u64>,
            events: Mutex<Vec<&'static str>>,
            current: PathBuf,
            identity: PathBuf,
            output: PathBuf,
            candidate: PathBuf,
            bound: PathBuf,
        }

        impl Fake {
            fn tick(&self, name: &'static str) -> Result<()> {
                self.events.lock().unwrap().push(name);
                require(self.failure != name)
            }
        }

        #[async_trait]
        impl Producers for Fake {
            async fn health(&self, expected: &Binding) -> Result<()> {
                assert_eq!(*expected, binding());
                self.tick("health")
            }
            async fn inventory(&self, _token: &str, current: &Path) -> Result<Vec<String>> {
                assert_eq!(current, self.current);
                self.tick("inventory")?;
                let mut result = names();
                if self.failure == "inventory-scope" {
                    result[0] = "broader-scope".into();
                }
                Ok(result)
            }
            async fn enroll(&self, identity: &Path, context: &Value) -> Result<()> {
                self.tick("enroll")?;
                assert_eq!(context["names"], json!(names()));
                assert_eq!(context["allow_secret_id_rotation"], false);
                identity_files(identity);
                if self.failure == "enroll-uncertain" {
                    return Err(REFUSAL);
                }
                Ok(())
            }
            async fn login(&self, identity: &Path, captured: &mut Option<String>) -> Result<Value> {
                assert_eq!(identity, self.identity);
                if self.failure == "unknown-login" {
                    self.events.lock().unwrap().push("login");
                    return Err(REFUSAL);
                }
                *captured = Some(LOGIN_TOKEN.into());
                self.tick("login")?;
                if self.failure == "session-write" {
                    put(
                        &self.output.join("authority.token"),
                        b"existing-private-evidence",
                        0o600,
                    );
                }
                Ok(json!({"token":LOGIN_TOKEN}))
            }
            async fn authority(&self, token: &str) -> Result<()> {
                assert_eq!(token, LOGIN_TOKEN);
                self.tick("authority")
            }
            fn executable(&self) -> Result<()> {
                self.tick("executable")
            }
            fn tls(&self, output: &Path, expected: &Binding, remaining: Duration) -> Result<()> {
                self.tick("tls")?;
                assert_eq!(*expected, binding());
                assert!(remaining <= Duration::from_secs(860));
                let (tls, _, tokens) = generation::inventories();
                for name in tls {
                    let value = if name == "workload_identity_ca_cert" {
                        if self.failure == "changed-ca" {
                            b"unapproved-ca".to_vec()
                        } else {
                            WORKLOAD_CA.to_vec()
                        }
                    } else if tokens.contains(&name) && self.failure == "shared-token" {
                        b"synthetic-new-shared-token-forbidden".to_vec()
                    } else {
                        format!("new-credential-{name}").into_bytes()
                    };
                    put(
                        &output.join("tls").join(name),
                        &value,
                        if self.failure == "tls-mode" {
                            0o444
                        } else {
                            0o600
                        },
                    );
                }
                let roles = marty_selfhost_identity::SELFHOST_ROLES
                    .iter()
                    .map(|role| json!({"role":role.name,"key_name":role.key_name,"version":1}))
                    .collect::<Vec<_>>();
                put(
                    &output.join("tls").join(TLS_METADATA),
                    &serde_json::to_vec(
                        &json!({"schema":"marty.selfhost-disposable-tls-keys/v1","roles":roles}),
                    )
                    .unwrap(),
                    0o600,
                );
                if self.failure == "tls-extra" {
                    put(&output.join("tls/unexpected"), b"unexpected", 0o600);
                }
                Ok(())
            }
            async fn keycloak(&self, token: &str, nonce: &str) -> Result<Value> {
                assert_eq!(token, LOGIN_TOKEN);
                assert_eq!(nonce, "123456abcdef");
                self.tick("keycloak")?;
                if self.failure == "identity-drift" {
                    put(
                        &self.identity.join("renewal-secret-id"),
                        b"changed-private-secret-id",
                        0o600,
                    );
                }
                if self.failure == "binding-drift" {
                    put(&self.bound, b"changed binding", 0o600);
                }
                if self.failure == "current-recreated" {
                    let before = snapshot(&self.current).unwrap();
                    fs::rename(&self.current, self.current.with_extension("moved")).unwrap();
                    fs::DirBuilder::new()
                        .mode(0o700)
                        .create(&self.current)
                        .unwrap();
                    for (name, (value, mode)) in before {
                        put(&self.current.join(name), &value, mode);
                    }
                }
                let (_, files, _) = generation::inventories();
                Ok(Value::Object(
                    files
                        .into_iter()
                        .map(|name| {
                            let value = format!("new-credential-{name}");
                            (name, json!(value))
                        })
                        .collect(),
                ))
            }
            async fn tokens(&self, checks: &Value) -> Result<Vec<String>> {
                self.tick("tokens")?;
                assert_eq!(checks["require_orphan_new"], true);
                assert_eq!(checks["require_orphan_old"], false);
                assert_eq!(checks["require_closed_new_metadata"], true);
                assert!(checks["minimum_ttl"].as_u64().unwrap() > 3600);
                let mut result = names();
                if self.failure == "token-scope" {
                    result[0] = "wrong-scope".into();
                }
                if self.failure == "verification-identity-drift" {
                    put(
                        &self.identity.join("renewal-secret-id"),
                        b"changed-private-secret-id",
                        0o600,
                    );
                }
                if self.failure == "verification-binding-drift" {
                    put(&self.bound, b"{}", 0o600);
                }
                Ok(result)
            }
            async fn certificates(&self, checks: &Value) -> Result<()> {
                assert_eq!(checks["replacement"], Value::Null);
                assert_eq!(checks["retiring"], false);
                self.tick("certificates")?;
                if let Some(ttl) = self.certificate_ttl {
                    use spki::der::{DecodePem, EncodePem};
                    use std::time::UNIX_EPOCH;
                    let now = Duration::from_secs(1_800_000_000);
                    let mut certificate = x509_cert::Certificate::from_pem(include_bytes!(
                        "../../../../tests/fixtures/selfhost_ca_issuer_public.pem"
                    ))
                    .unwrap();
                    certificate.tbs_certificate.validity.not_before =
                        (UNIX_EPOCH + now).try_into().unwrap();
                    certificate.tbs_certificate.validity.not_after =
                        (UNIX_EPOCH + now + Duration::from_secs(ttl))
                            .try_into()
                            .unwrap();
                    let pem = certificate.to_pem(spki::der::pem::LineEnding::LF).unwrap();
                    assert_eq!(checks["minimum_ttl"], 4500);
                    require(crate::operator_certificates::check_lifetime_at(
                        pem.as_bytes(),
                        checks["minimum_ttl"].as_u64().unwrap(),
                        now,
                    )?)?;
                    // The same proof must leave the public floor after the
                    // complete outer activation budget has elapsed.
                    assert!(crate::operator_certificates::check_lifetime_at(
                        pem.as_bytes(),
                        MINIMUM_TTL,
                        now + Duration::from_secs(OPERATION_SECONDS),
                    )
                    .unwrap());
                }
                if self.failure == "validated-write" {
                    put(
                        &self.output.join("validated.json"),
                        b"existing-private-evidence",
                        0o600,
                    );
                }
                Ok(())
            }
            async fn retire(&self, token: &str) -> Result<()> {
                assert_eq!(token, LOGIN_TOKEN);
                self.tick("retire")?;
                if self.failure == "late-input-drift" {
                    put(
                        &self.current.join("ordinary_token"),
                        b"intervening-token",
                        0o440,
                    );
                }
                if self.failure == "candidate-drift" {
                    put(
                        &self.candidate.join("ordinary_token"),
                        b"intervening-token",
                        0o440,
                    );
                }
                Ok(())
            }
        }

        #[tokio::test]
        async fn verification_keeps_the_lifetime_floor_through_the_whole_activation_window() {
            for (ttl, accepted) in [(4499, false), (4500, true), (4501, true)] {
                let fixture = Fixture::new();
                let context = fixture.verification();
                let mut api = fixture.fake("");
                api.certificate_ttl = Some(ttl);
                let result = verify_with(&api, &fixture.ca, CA, &fixture.identity, context).await;
                assert_eq!(result.is_ok(), accepted, "certificate TTL {ttl}");
                assert_eq!(fixture.output.join("completed.json").exists(), accepted);
                assert_eq!(
                    api.events
                        .lock()
                        .unwrap()
                        .iter()
                        .filter(|event| **event == "retire")
                        .count(),
                    1
                );
                assert!(fixture.output.join("session-retired.json").exists());
            }
        }

        #[tokio::test]
        async fn fresh_verification_is_read_only_and_retires_the_known_session_before_completion() {
            let fixture = Fixture::new();
            let context = fixture.verification();
            let before = snapshot(&fixture.current).unwrap();
            let candidate = snapshot(&fixture.candidate).unwrap();
            let credentials = snapshot(&fixture.identity).unwrap();
            let api = fixture.fake("");
            let result = verify_with(&api, &fixture.ca, CA, &fixture.identity, context)
                .await
                .unwrap();
            assert_eq!(
                result,
                json!({"ready":true,"count":39,"minimumTtlSeconds":3600})
            );
            assert_eq!(
                *api.events.lock().unwrap(),
                [
                    "health",
                    "login",
                    "health",
                    "authority",
                    "tokens",
                    "certificates",
                    "health",
                    "retire"
                ]
            );
            assert_eq!(snapshot(&fixture.current).unwrap(), before);
            assert_eq!(snapshot(&fixture.candidate).unwrap(), candidate);
            assert_eq!(snapshot(&fixture.identity).unwrap(), credentials);
            let evidence = snapshot(&fixture.output).unwrap();
            assert_eq!(
                evidence.keys().map(String::as_str).collect::<Vec<_>>(),
                [
                    "authority.token",
                    "completed.json",
                    "pending.json",
                    "session-retired.json",
                    "validated.json"
                ]
            );
            assert!(evidence.values().all(|entry| entry.1 == 0o600));
            let completed: Value = serde_json::from_slice(&evidence["completed.json"].0).unwrap();
            assert_eq!(
                completed,
                json!({
                    "schema":"marty.kubernetes-renewal-verification/v1","binding":binding(),
                    "producerNonce":"123456abcdef","files":43,"changedFiles":39,"scopedLeafTokens":21,
                    "transientRevoked":true,"activated":false,"caChanged":false,"minimumTtlSeconds":3600,
                })
            );
            let retired: Value =
                serde_json::from_slice(&evidence["session-retired.json"].0).unwrap();
            assert_eq!(
                retired,
                json!({"schema":"marty.kubernetes-renewal-session-retirement/v1",
                "transientRevoked":true})
            );
            assert!(!result.to_string().contains(LOGIN_TOKEN));
        }

        #[tokio::test]
        async fn verification_failure_always_retires_known_sessions_without_producing_or_completing(
        ) {
            for fault in [
                "login",
                "session-write",
                "authority",
                "tokens",
                "token-scope",
                "certificates",
                "validated-write",
                "retire",
                "late-input-drift",
                "candidate-drift",
                "verification-identity-drift",
                "verification-binding-drift",
                "session-in-candidate",
            ] {
                let fixture = Fixture::new();
                let context = fixture.verification();
                if fault == "session-in-candidate" {
                    let path = fixture.candidate.join("keycloak_master_rs256_cert");
                    let mode =
                        snapshot(&fixture.candidate).unwrap()["keycloak_master_rs256_cert"].1;
                    put(&path, LOGIN_TOKEN.as_bytes(), mode);
                }
                let api = fixture.fake(fault);
                assert_eq!(
                    verify_with(&api, &fixture.ca, CA, &fixture.identity, context).await,
                    Err(RECOVERY),
                    "{fault}"
                );
                let events = api.events.lock().unwrap();
                assert_eq!(
                    events.iter().filter(|event| **event == "retire").count(),
                    1,
                    "{fault}"
                );
                assert!(events.iter().all(|event| ![
                    "inventory",
                    "enroll",
                    "executable",
                    "tls",
                    "keycloak"
                ]
                .contains(event)));
                assert!(fixture.output.join("pending.json").exists(), "{fault}");
                assert!(!fixture.output.join("completed.json").exists(), "{fault}");
                assert_eq!(
                    fixture.output.join("session-retired.json").exists(),
                    fault != "retire",
                    "{fault}"
                );
            }
        }

        #[tokio::test]
        async fn unknown_verification_login_retains_one_intent_and_cannot_be_replayed() {
            let fixture = Fixture::new();
            let context = fixture.verification();
            let api = fixture.fake("unknown-login");
            assert_eq!(
                verify_with(&api, &fixture.ca, CA, &fixture.identity, context).await,
                Err(RECOVERY)
            );
            assert_eq!(*api.events.lock().unwrap(), ["health", "login"]);
            assert_eq!(
                generation::entries(&fixture.output)
                    .unwrap()
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                ["pending.json"]
            );
            assert!(
                verify_with(&api, &fixture.ca, CA, &fixture.identity, fixture.staging())
                    .await
                    .is_err()
            );
            assert_eq!(*api.events.lock().unwrap(), ["health", "login"]);
        }

        #[tokio::test]
        async fn verification_rejects_generation_binding_and_custody_faults_before_any_session() {
            for fault in [
                "ordinary-change",
                "ca-change",
                "missing-input",
                "wrong-mode",
                "identity-extra",
                "binding",
                "ca",
                "output-overlap",
                "candidate-alias",
                "budget-zero",
                "budget-large",
                "health",
            ] {
                let fixture = Fixture::new();
                let mut context = fixture.verification();
                match fault {
                    "ordinary-change" => put(
                        &fixture.candidate.join("ordinary_token"),
                        b"unrelated-change",
                        0o440,
                    ),
                    "ca-change" => put(
                        &fixture.candidate.join("workload_identity_ca_cert"),
                        b"unapproved-ca",
                        0o444,
                    ),
                    "missing-input" => {
                        fs::remove_file(fixture.candidate.join("keycloak_master_cookie_token"))
                            .unwrap()
                    }
                    "wrong-mode" => fs::set_permissions(
                        fixture.candidate.join("keycloak_master_cookie_token"),
                        fs::Permissions::from_mode(0o666),
                    )
                    .unwrap(),
                    "identity-extra" => put(&fixture.identity.join("extra"), b"extra", 0o600),
                    "binding" => {
                        context.binding.namespace_uid =
                            "00000000-2222-3333-4444-555555555555".into()
                    }
                    "ca" => put(&fixture.ca, b"wrong-ca", 0o600),
                    "output-overlap" => context.output = fixture.candidate.clone(),
                    "candidate-alias" => {
                        let path = fixture._root.path().join("alias");
                        symlink(&fixture.candidate, &path).unwrap();
                        context.candidate = path;
                    }
                    "budget-zero" => context.budget_seconds = 0,
                    "budget-large" => context.budget_seconds = 901,
                    "health" => {}
                    _ => unreachable!(),
                }
                let api = fixture.fake(fault);
                assert!(
                    verify_with(&api, &fixture.ca, CA, &fixture.identity, context)
                        .await
                        .is_err(),
                    "{fault}"
                );
                assert!(!api.events.lock().unwrap().contains(&"login"), "{fault}");
                assert!(!fixture.output.join("pending.json").exists(), "{fault}");
            }
        }

        #[tokio::test]
        async fn staging_preserves_entire_generation_and_retires_only_owned_session() {
            let fixture = Fixture::new();
            let before = snapshot(&fixture.current).unwrap();
            let api = fixture.fake("");
            let response = stage_with(&api, &fixture.ca, CA, &fixture.identity, fixture.staging())
                .await
                .unwrap();
            assert_eq!(
                response,
                json!({"ready":true,"candidate":fixture.candidate,
                "count":43,"changed":39,"transientRevoked":true})
            );
            assert_eq!(snapshot(&fixture.current).unwrap(), before);
            assert_eq!(
                generation::verify(&fixture.current, &fixture.candidate, false, false).unwrap(),
                (43, 39)
            );
            for name in [
                "workload_identity_ca_cert",
                "openbao_tls_ca_cert",
                "ordinary_token",
                "unrelated_empty",
            ] {
                assert_eq!(snapshot(&fixture.candidate).unwrap()[name], before[name]);
            }
            let events = api.events.lock().unwrap();
            assert_eq!(events.iter().filter(|event| **event == "retire").count(), 1);
            assert_eq!(events.last(), Some(&"retire"));
            let completed: Value = serde_json::from_slice(
                &input(&fixture.output.join("completed.json"), 4096).unwrap(),
            )
            .unwrap();
            assert_eq!(completed["transientRevoked"], true);
            assert_eq!(completed["activated"], false);
            assert_eq!(completed["caChanged"], false);
            assert!(!response.to_string().contains(LOGIN_TOKEN));
        }

        #[tokio::test]
        async fn every_known_session_failure_attempts_retirement_and_never_completes() {
            for fault in [
                "login",
                "authority",
                "inventory",
                "inventory-scope",
                "tls",
                "keycloak",
                "tokens",
                "token-scope",
                "certificates",
                "retire",
                "session-write",
                "validated-write",
                "changed-ca",
                "shared-token",
                "tls-mode",
                "tls-extra",
                "identity-drift",
                "binding-drift",
                "current-recreated",
                "late-input-drift",
                "candidate-drift",
            ] {
                let fixture = Fixture::new();
                let api = fixture.fake(fault);
                assert_eq!(
                    stage_with(&api, &fixture.ca, CA, &fixture.identity, fixture.staging()).await,
                    Err(RECOVERY),
                    "{fault}"
                );
                let events = api.events.lock().unwrap();
                assert_eq!(
                    events.iter().filter(|event| **event == "retire").count(),
                    1,
                    "{fault}"
                );
                assert!(fixture.output.join("pending.json").exists(), "{fault}");
                assert!(!fixture.output.join("completed.json").exists(), "{fault}");
                assert_eq!(
                    fixture.output.join("session-retired.json").exists(),
                    fault != "retire",
                    "{fault}"
                );
            }
        }

        #[tokio::test]
        async fn unknown_login_retains_intent_without_claiming_retirement_or_replaying() {
            let fixture = Fixture::new();
            let api = fixture.fake("unknown-login");
            assert_eq!(
                stage_with(&api, &fixture.ca, CA, &fixture.identity, fixture.staging()).await,
                Err(RECOVERY)
            );
            {
                let events = api.events.lock().unwrap();
                assert_eq!(events.iter().filter(|event| **event == "login").count(), 1);
                assert!(!events.contains(&"retire"));
            }
            assert_eq!(
                generation::entries(&fixture.output)
                    .unwrap()
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>(),
                ["pending.json"]
            );
            assert!(
                stage_with(&api, &fixture.ca, CA, &fixture.identity, fixture.staging())
                    .await
                    .is_err()
            );
            assert_eq!(
                api.events
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|event| **event == "login")
                    .count(),
                1
            );
        }

        #[tokio::test]
        async fn wrong_binding_identity_or_transport_custody_refuses_before_login() {
            for fault in [
                "nonce",
                "namespace-uid",
                "cluster",
                "binding-extra",
                "identity-extra",
                "identity-hardlink",
                "identity-mode",
                "identity-policy",
                "ca",
                "current-symlink",
                "parent-alias",
                "budget-zero",
                "budget-large",
            ] {
                let fixture = Fixture::new();
                let mut context = fixture.staging();
                match fault {
                    "nonce" => {
                        context.binding.workload_project =
                            "marty-selfhost-disposable-k8s-abcdefabcdef".into()
                    }
                    "namespace-uid" => {
                        context.binding.namespace_uid =
                            "00000000-2222-3333-4444-555555555555".into()
                    }
                    "cluster" => {
                        context.binding.openbao_cluster_id =
                            "00000000-bbbb-cccc-dddd-eeeeeeeeeeee".into()
                    }
                    "binding-extra" => {
                        let mut value: Value =
                            serde_json::from_slice(&input(&fixture.bound, 4096).unwrap()).unwrap();
                        value["root_token"] = json!("forbidden");
                        put(&fixture.bound, &serde_json::to_vec(&value).unwrap(), 0o600);
                    }
                    "identity-extra" => {
                        put(&fixture.identity.join("unexpected"), b"unexpected", 0o600)
                    }
                    "identity-hardlink" => fs::hard_link(
                        fixture.identity.join("renewal-secret-id"),
                        fixture._root.path().join("linked"),
                    )
                    .unwrap(),
                    "identity-mode" => fs::set_permissions(
                        fixture.identity.join("renewal-secret-id"),
                        fs::Permissions::from_mode(0o644),
                    )
                    .unwrap(),
                    "identity-policy" => {
                        let mut values = names();
                        values.push("installer-ingress-12345678123442348234123456789abc".into());
                        put(
                            &fixture.identity.join(IDENTITY_FILES[0]),
                            &serde_json::to_vec(&values).unwrap(),
                            0o600,
                        );
                    }
                    "ca" => put(&fixture.ca, b"wrong-public-ca", 0o600),
                    "current-symlink" => {
                        symlink(&fixture.ca, fixture.current.join("linked")).unwrap()
                    }
                    "parent-alias" => {
                        let alias = fixture._root.path().join("alias");
                        symlink(&fixture.current, &alias).unwrap();
                        context.current = alias;
                    }
                    "budget-zero" => context.budget_seconds = 0,
                    "budget-large" => context.budget_seconds = 901,
                    _ => unreachable!(),
                }
                let api = fixture.fake("");
                assert!(
                    stage_with(&api, &fixture.ca, CA, &fixture.identity, context)
                        .await
                        .is_err(),
                    "{fault}"
                );
                assert!(!api.events.lock().unwrap().contains(&"login"), "{fault}");
                assert!(!fixture.output.join("completed.json").exists(), "{fault}");
            }
        }

        #[tokio::test]
        async fn enrollment_uses_existing_three_file_identity_and_separate_binding() {
            for fault in ["", "enroll-uncertain"] {
                let fixture = Fixture::new();
                for name in IDENTITY_FILES {
                    fs::remove_file(fixture.identity.join(name)).unwrap();
                }
                let api = fixture.fake(fault);
                let root_token = "synthetic-root-ceremony-token-not-retained";
                let result = enroll_with(
                    &api,
                    &fixture.ca,
                    CA,
                    &fixture.identity,
                    Enrollment {
                        root_token: root_token.into(),
                        current: fixture.current.clone(),
                        output: fixture.output.clone(),
                        binding: binding(),
                    },
                )
                .await;
                assert_eq!(result.is_ok(), fault.is_empty());
                assert_eq!(
                    fixture.output.join("completed.json").exists(),
                    fault.is_empty()
                );
                assert_eq!(
                    fixture.output.join("binding.json").exists(),
                    fault.is_empty()
                );
                assert!(fixture.output.join("pending.json").exists());
                assert_eq!(
                    generation::entries(&fixture.identity)
                        .unwrap()
                        .keys()
                        .map(String::as_str)
                        .collect::<Vec<_>>(),
                    IDENTITY_FILES
                );
                for directory in [&fixture.identity, &fixture.output] {
                    for entry in generation::entries(directory).unwrap().values() {
                        assert!(!String::from_utf8(input(entry, 65536).unwrap())
                            .unwrap()
                            .contains(root_token));
                    }
                }
                assert!(!api.events.lock().unwrap().contains(&"login"));
            }
        }

        #[test]
        fn original_project_and_nonce_are_never_replaced_with_transport_identity() {
            let binding = binding();
            let env = workload_environment(
                "https://openbao:8200",
                Path::new("/tmp/ca.crt"),
                Path::new("/tmp/renewal-operation"),
                &binding,
            );
            assert_eq!(env["MARTY_SELFHOST_PROJECT"], binding.workload_project);
            assert_eq!(env["MARTY_TLS_BOOTSTRAP_PROFILE"], "selfhost-renew");
            assert_eq!(env["MARTY_SELFHOST_WORKLOAD_PKI_MOUNT"], "workload-pki");
            assert_eq!(
                env["BAO_RENEWAL_TOKEN_FILE"],
                "/tmp/renewal-operation/authority.token"
            );
            assert_eq!(nonce(&binding).unwrap(), "123456abcdef");
            assert!(!env
                .keys()
                .any(|name| name.contains("ROOT") || name.contains("PROXY")));
            assert!(!env.values().any(|value| value.contains(LOGIN_TOKEN)));
        }

        #[test]
        fn terminal_deadline_failure_removes_only_its_own_receipt() {
            let fixture = Fixture::new();
            let output = HeldDirectory::open(&fixture.output, true).unwrap();
            receipt(&output, "pending.json", &json!({"pending":true}), 4096).unwrap();
            let past = Instant::now() - Duration::from_secs(1);
            let budget = Budget {
                deadline: past,
                work_deadline: past,
            };
            assert!(terminal_receipt(&output, &json!({"complete":true}), &budget).is_err());
            assert!(!fixture.output.join("completed.json").exists());
            assert!(fixture.output.join("pending.json").exists());
            put(
                &fixture.output.join("completed.json"),
                b"existing-private-evidence",
                0o600,
            );
            assert!(terminal_receipt(
                &output,
                &json!({"complete":true}),
                &Budget::new(900).unwrap()
            )
            .is_err());
            assert_eq!(
                input(&fixture.output.join("completed.json"), 4096).unwrap(),
                b"existing-private-evidence"
            );
        }

        #[tokio::test]
        async fn expired_work_budget_keeps_cleanup_reserve_without_resetting_deadline() {
            let budget = Budget {
                deadline: Instant::now() + Duration::from_secs(1),
                work_deadline: Instant::now() - Duration::from_secs(1),
            };
            assert!(budget.run(false, async { Ok(()) }).await.is_err());
            assert!(budget.run(true, async { Ok(()) }).await.is_ok());
            assert!(budget.verification_ttl().unwrap() > MINIMUM_TTL);
            assert!(Budget::new(59).is_err());
            assert!(Budget::new(901).is_err());
        }
    }
}
