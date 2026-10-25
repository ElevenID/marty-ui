//! Deterministic deployment admission. Live cluster/file observations stay at callers.
use super::passport_model::{require, PolicyResult};
use serde_json::{json, Value};
use std::collections::HashSet;

const SERVICES: [&str; 6] = [
    "gateway",
    "flow",
    "issuance-native",
    "signing-keys",
    "passport-callback-signer",
    "passport-beta-bureau",
];
fn port(name: &str) -> Option<u64> {
    Some(match name {
        "gateway" => 8000,
        "flow" => 8011,
        "issuance-native" => 8005,
        "signing-keys" => 8017,
        "passport-callback-signer" => 8018,
        "passport-beta-bureau" => 8020,
        _ => return None,
    })
}
fn empty(v: Option<&Value>, fallback: &Value) -> bool {
    v.is_none_or(|v| v.is_null() || v == fallback)
}
fn keys(v: &Value, allowed: &[&str]) -> bool {
    v.as_object()
        .is_some_and(|m| m.keys().all(|k| allowed.contains(&k.as_str())))
}
fn exact_keys(v: &Value, expected: &[&str]) -> bool {
    v.as_object().is_some_and(|m| {
        m.len() == expected.len() && m.keys().all(|k| expected.contains(&k.as_str()))
    })
}
fn pattern(s: &str, p: &str) -> bool {
    regex::Regex::new(p).unwrap().is_match(s)
}
fn string_pattern(v: &Value, p: &str) -> bool {
    v.as_str().is_some_and(|s| pattern(s, p))
}
fn routing(name: &str) -> bool {
    // Full case-fold expansions that can form these closed ASCII keywords.
    let name = name
        .to_lowercase()
        .replace('\u{00df}', "ss")
        .replace('\u{017f}', "s")
        .replace('\u{fb00}', "ff")
        .replace('\u{fb01}', "fi")
        .replace('\u{fb02}', "fl")
        .replace('\u{fb03}', "ffi")
        .replace('\u{fb04}', "ffl")
        .replace(['\u{fb05}', '\u{fb06}'], "st");
    name == "proxy"
        || name.ends_with("_proxy")
        || ["hostaliases", "res_options", "localdomain"].contains(&name.as_str())
}
fn probe(v: &Value, p: u64) -> bool {
    if v.is_null() {
        return true;
    }
    if !keys(
        v,
        &[
            "httpGet",
            "initialDelaySeconds",
            "periodSeconds",
            "timeoutSeconds",
            "successThreshold",
            "failureThreshold",
            "terminationGracePeriodSeconds",
        ],
    ) {
        return false;
    }
    let r = &v["httpGet"];
    keys(r, &["path", "port", "scheme", "host", "httpHeaders"])
        && r["path"] == "/health"
        && r["port"] == p
        && empty(r.get("scheme"), &json!("HTTP"))
        && empty(r.get("host"), &json!(""))
        && empty(r.get("httpHeaders"), &json!([]))
        && v.as_object()
            .unwrap()
            .iter()
            .all(|(k, v)| k == "httpGet" || v.as_u64().is_some())
}
fn entrypoint(v: &Value) -> bool {
    let Some(p) = v["name"].as_str().and_then(port) else {
        return false;
    };
    if !v.is_object()
        || !empty(v.get("command"), &json!(["/app/services/entrypoint.sh"]))
        || !empty(v.get("args"), &json!([]))
        || !empty(v.get("lifecycle"), &json!({}))
        || ["startupProbe", "readinessProbe", "livenessProbe"]
            .iter()
            .any(|k| !probe(&v[k], p))
    {
        return false;
    }
    let none = vec![];
    let mounts = match v.get("volumeMounts") {
        None => &none,
        Some(x) => match x.as_array() {
            Some(x) => x,
            None => return false,
        },
    };
    let env = match v.get("env") {
        None => &none,
        Some(x) => match x.as_array() {
            Some(x) => x,
            None => return false,
        },
    };
    let sources = match v.get("envFrom") {
        None => &none,
        Some(x) => match x.as_array() {
            Some(x) => x,
            None => return false,
        },
    };
    env.iter().all(|e| {
        e.is_object()
            && e["name"]
                .as_str()
                .is_some_and(|n| n != "PATH" && !n.starts_with("LD_") && !routing(n))
    }) && sources
        .iter()
        .all(|s| s.is_object() && s["configMapRef"] == json!({"name":"marty-config"}))
        && mounts.iter().all(|m| {
            m.is_object()
                && m["readOnly"] == true
                && m["mountPath"].as_str().is_some_and(|p| {
                    p.starts_with("/run/secrets/")
                        && p[1..]
                            .split('/')
                            .all(|s| !s.is_empty() && s != "." && s != "..")
                })
        })
}
fn runtime(v: &Value) -> bool {
    let pod = &v["securityContext"];
    if !v.is_object()
        || !pod.is_object()
        || pod["runAsNonRoot"] != true
        || pod["runAsUser"] != 10001
        || pod["runAsGroup"] != 10001
        || v["automountServiceAccountToken"] != false
    {
        return false;
    }
    for k in ["hostNetwork", "hostPID", "hostIPC", "shareProcessNamespace"] {
        if !empty(v.get(k), &json!(false)) {
            return false;
        }
    }
    for k in ["hostAliases", "initContainers", "ephemeralContainers"] {
        if !empty(v.get(k), &json!([])) {
            return false;
        }
    }
    if !empty(v.get("dnsPolicy"), &json!("ClusterFirst")) || !empty(v.get("dnsConfig"), &json!({}))
    {
        return false;
    }
    let Some(containers) = v["containers"]
        .as_array()
        .filter(|a| a.len() == 1 && a[0].is_object())
    else {
        return false;
    };
    let c = &containers[0];
    let none = vec![];
    let array = |k| match v.get(k) {
        None => Some(&none),
        Some(x) => x.as_array(),
    };
    let Some(volumes) = array("volumes") else {
        return false;
    };
    let mounts = match c.get("volumeMounts") {
        None => &none,
        Some(x) => match x.as_array() {
            Some(x) => x,
            None => return false,
        },
    };
    let ports = match c.get("ports") {
        None => &none,
        Some(x) => match x.as_array() {
            Some(x) => x,
            None => return false,
        },
    };
    if !ports.iter().all(|p| {
        p.is_object() && empty(p.get("hostPort"), &json!(0)) && empty(p.get("hostIP"), &json!(""))
    }) {
        return false;
    }
    let names = |items: &Vec<Value>| {
        items
            .iter()
            .map(|v| v["name"].as_str().map(str::to_owned))
            .collect::<Option<HashSet<_>>>()
    };
    let (Some(mounted), Some(defined)) = (names(mounts), names(volumes)) else {
        return false;
    };
    if mounted.len() != mounts.len() || defined.len() != volumes.len() || mounted != defined {
        return false;
    }
    if !volumes.iter().all(|vol| {
        exact_keys(vol, &["name", "secret"])
            && string_pattern(&vol["name"], r"\A[a-z0-9]([-a-z0-9]*[a-z0-9])?\z")
            && keys(
                &vol["secret"],
                &["secretName", "items", "defaultMode", "optional"],
            )
            && string_pattern(
                &vol["secret"]["secretName"],
                r"\Apassport-acceptance-[a-z0-9-]+\z",
            )
            && empty(vol["secret"].get("optional"), &json!(false))
    }) {
        return false;
    }
    let s = &c["securityContext"];
    s.is_object()
        && s["readOnlyRootFilesystem"] == true
        && s["allowPrivilegeEscalation"] == false
        && empty(s.get("privileged"), &json!(false))
        && empty(s.get("runAsNonRoot"), &json!(true))
        && empty(s.get("runAsUser"), &json!(10001))
        && empty(s.get("runAsGroup"), &json!(10001))
        && empty(s.get("procMount"), &json!("Default"))
        && s["capabilities"].is_object()
        && s["capabilities"]["drop"] == json!(["ALL"])
        && empty(s["capabilities"].get("add"), &json!([]))
}
fn config(input: &Value) -> PolicyResult {
    let c = &input["container"];
    let data = &input["data"];
    let name = input["name"]
        .as_str()
        .ok_or("Kubernetes passport configuration name is invalid")?;
    let none = vec![];
    let entries = match c.get("env") {
        None => &none,
        Some(x) => x
            .as_array()
            .ok_or("Kubernetes passport environment is invalid")?,
    };
    let matches = entries
        .iter()
        .filter(|e| e.is_object() && e["name"] == name)
        .collect::<Vec<_>>();
    require(
        matches.len() <= 1,
        "Kubernetes passport environment is ambiguous",
    )?;
    if let Some(e) = matches.first() {
        if let Some(v) = e.get("value") {
            require(
                e.get("valueFrom").is_none(),
                "Kubernetes passport configuration source is ambiguous",
            )?;
            return Ok(v.clone());
        }
        let source = &e["valueFrom"]["configMapKeyRef"];
        require(
            source.is_object() && source["name"] == "marty-config" && source["key"] == name,
            "Kubernetes passport configuration source is invalid",
        )?;
    } else {
        let sources = match c.get("envFrom") {
            None => &none,
            Some(x) => x
                .as_array()
                .ok_or("Kubernetes passport environment source is invalid")?,
        };
        require(
            sources.len() == 1
                && sources[0].is_object()
                && sources[0]["configMapRef"].is_object()
                && sources[0]["configMapRef"]["name"] == "marty-config",
            "Kubernetes passport ConfigMap source is ambiguous",
        )?;
    }
    require(
        data.is_object(),
        "Kubernetes passport configuration data is invalid",
    )?;
    Ok(data.get(name).cloned().unwrap_or(Value::Null))
}
// Check the raw authority/path before URL parsing can normalize dot segments,
// backslashes, or empty userinfo into a different admitted server identity.
fn cluster_server(server: &str) -> bool {
    let Some((_, rest)) = server.split_once("://") else {
        return false;
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let tail = &rest[authority_end..];
    let raw_path = tail.split(['?', '#']).next().unwrap_or("");
    if authority.contains(['@', '\\']) || !raw_path.trim_matches('/').is_empty() {
        return false;
    }
    url::Url::parse(server).is_ok_and(|u| {
        u.scheme() == "https"
            && u.host_str().is_some()
            && u.username().is_empty()
            && u.password().is_none()
            && u.query().is_none_or(str::is_empty)
    })
}
fn plan(input: &Value) -> PolicyResult {
    let p = &input["plan"];
    let source = &input["source_commit"];
    let image = &input["services_reference"];
    require(
        exact_keys(
            p,
            &[
                "schema",
                "status",
                "source_commit",
                "plan_run_id",
                "services_reference",
                "cluster",
                "namespace",
                "resources",
            ],
        ) && p["schema"] == "marty.passport-supported-kubernetes-model/v1"
            && p["status"] == "blocked"
            && p["source_commit"] == *source
            && string_pattern(source, r"\A[0-9a-f]{40}\z")
            && string_pattern(&p["plan_run_id"], r"\A[1-9][0-9]{0,19}\z")
            && p["services_reference"] == *image
            && string_pattern(
                image,
                r"\Aghcr\.io/elevenid/marty-ui-oss/services@sha256:[0-9a-f]{64}\z",
            ),
        "Disposable Kubernetes plan source or images are invalid",
    )?;
    let c = &p["cluster"];
    let n = &p["namespace"];
    let disposable = r"\Amarty-passport-acceptance-[a-z0-9]{6,32}\z";
    let uid = r"\A[a-zA-Z0-9][a-zA-Z0-9-]{7,127}\z";
    require(
        exact_keys(c, &["context", "name", "server", "ca_sha256"])
            && string_pattern(&c["context"], disposable)
            && string_pattern(&c["name"], disposable)
            && string_pattern(&c["ca_sha256"], r"\Asha256:[0-9a-f]{64}\z")
            && c["server"].as_str().is_some_and(cluster_server),
        "Disposable Kubernetes cluster identity is invalid",
    )?;
    require(
        exact_keys(n, &["name", "uid"])
            && string_pattern(&n["name"], disposable)
            && string_pattern(&n["uid"], uid),
        "Disposable Kubernetes namespace identity is invalid",
    )?;
    let mut expected = HashSet::from([
        "configmap/marty-config".to_owned(),
        "networkpolicy/passport-acceptance-callback-signer-ingress".to_owned(),
    ]);
    for service in SERVICES {
        for kind in ["deployment", "service"] {
            expected.insert(format!("{kind}/{service}"));
        }
    }
    require(
        p["resources"].as_object().is_some_and(|m| {
            m.keys().cloned().collect::<HashSet<_>>() == expected
                && m.values().all(|v| string_pattern(v, uid))
                && m.values()
                    .filter_map(Value::as_str)
                    .collect::<HashSet<_>>()
                    .len()
                    == m.len()
        }),
        "Disposable Kubernetes resource identities are invalid",
    )?;
    Ok(Value::Null)
}
pub(super) fn evaluate(op: &str, input: &Value) -> PolicyResult {
    match op {
        "kubernetes-routing-env" => Ok(json!(routing(
            input["name"].as_str().ok_or("Invalid environment name")?
        ))),
        "kubernetes-health-probe" => Ok(json!(input["port"]
            .as_u64()
            .is_some_and(|p| probe(&input["probe"], p)))),
        "kubernetes-entrypoint" => Ok(json!(entrypoint(&input["container"]))),
        "kubernetes-runtime" => Ok(json!(runtime(&input["spec"]))),
        "kubernetes-config" => config(input),
        "kubernetes-plan" => plan(input),
        "selfhost-credential-admission" => {
            let key = input["credential"]
                .as_str()
                .ok_or("Invalid credential admission")?;
            let others = input["others"]
                .as_array()
                .ok_or("Invalid credential admission")?;
            Ok(json!(
                key.len() >= 32 && others.iter().all(|v| v.as_str().is_some_and(|v| v != key))
            ))
        }
        "selfhost-credentials-distinct" => {
            let a = input["values"]
                .as_array()
                .ok_or("Invalid credential admission")?;
            let names = a.iter().filter_map(Value::as_str).collect::<HashSet<_>>();
            Ok(json!(names.len() == a.len()))
        }
        _ => Err("Deployment admission operation is invalid".into()),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn routing_aliases_remain_forbidden() {
        for s in [
            "HTTP_PROXY",
            "ho\u{017f}taliases",
            "ho\u{fb05}aliases",
            "RES_OPTIONS",
            "LOCALDOMAIN",
        ] {
            assert!(routing(s));
        }
        assert!(!routing("PUBLIC_DOMAIN"));
    }
    #[test]
    fn cluster_server_rejects_normalized_paths_and_userinfo() {
        for server in [
            "https://host/../",
            "https://host/%2e%2e/",
            "https://host/a/../",
            "https://@host",
            "https://user@host",
            "https://host/path",
            "https://host?query",
            "http://host",
            "https://host\\path",
        ] {
            assert!(!cluster_server(server), "{server}");
        }
        for server in [
            "https://host",
            "https://host/",
            "https://host///",
            "https://host?",
            "https://host/#fragment",
        ] {
            assert!(cluster_server(server), "{server}");
        }
    }
    #[test]
    fn probes_reject_boolean_thresholds_and_redirected_health() {
        assert!(probe(
            &json!({"httpGet":{"path":"/health","port":8000}}),
            8000
        ));
        assert!(!probe(
            &json!({"httpGet":{"path":"/health","port":8000},"periodSeconds":true}),
            8000
        ));
        assert!(!probe(
            &json!({"httpGet":{"path":"/health","port":8000,"host":"elsewhere"}}),
            8000
        ));
    }
    #[test]
    fn entrypoint_cannot_shadow_executable_or_inject_proxy() {
        let base = json!({"name":"gateway"});
        assert!(entrypoint(&base));
        for mount in [
            "/usr/local/bin",
            "/run/secrets/../bin",
            "/run/secrets/file/",
        ] {
            let mut c = base.clone();
            c["volumeMounts"] = json!([{"mountPath":mount,"readOnly":true}]);
            assert!(!entrypoint(&c));
        }
        let mut c = base;
        c["env"] = json!([{"name":"HTTP_PROXY","value":""}]);
        assert!(!entrypoint(&c));
    }
}
