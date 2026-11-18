//! CI-only libtest policy; process ownership and scheduling stay with callers.
use regex::Regex;
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    io::{self, Read},
};
type Result<T> = std::result::Result<T, &'static str>;
const CASE: &str = r"[A-Za-z_][A-Za-z0-9_:]*";
fn regex(pattern: &str) -> Regex {
    Regex::new(pattern).unwrap()
}
fn strings(v: &Value) -> Result<Vec<&str>> {
    v.as_array()
        .ok_or("invalid_policy_input")?
        .iter()
        .map(|v| v.as_str().ok_or("invalid_policy_input"))
        .collect()
}
fn selection(v: &Value) -> Result<Value> {
    let mut mode = "default";
    let mut selectors = Vec::new();
    let mut skip = false;
    let case = regex(&format!(r"\A{CASE}\z"));
    let threads = regex(r"\A--test-threads=[1-9][0-9]*\z");
    for arg in strings(&v["arguments"])? {
        if skip {
            if !case.is_match(arg) {
                return Err("invalid_skip_selector");
            }
            selectors.push(arg);
            skip = false;
            continue;
        }
        if arg == "--skip" {
            if v["allow_skip"] != true {
                return Err("unsupported_selection_argument");
            }
            selectors.push(arg);
            skip = true;
            continue;
        }
        if arg == "--ignored" || arg == "--include-ignored" {
            if mode != "default" {
                return Err("ambiguous_ignored_selection");
            }
            mode = &arg[2..];
        } else if arg == "--exact"
            || (arg == "--nocapture" && v["allow_nocapture"] == true)
            || threads.is_match(arg)
            || case.is_match(arg)
        {
            selectors.push(arg);
        } else {
            return Err("unsupported_selection_argument");
        }
    }
    if skip {
        return Err("missing_skip_selector");
    }
    Ok(json!([selectors, mode]))
}
fn listing(v: &Value) -> Result<Value> {
    let case = regex(&format!(r"\A({CASE}): test\z"));
    let summary = regex(r"\A[0-9]+ tests?, [0-9]+ benchmarks?\z");
    let mut cases = BTreeSet::new();
    for line in strings(&v["lines"])? {
        if let Some(m) = case.captures(line) {
            if !cases.insert(m[1].to_owned()) {
                return Err("duplicate_discovered_case");
            }
        } else if !line.is_empty() && !summary.is_match(line) {
            return Err("unrecognized_libtest_discovery");
        }
    }
    Ok(json!(cases))
}
// Pinned stable libtest's separate logfile is not corrupted by inherited child
// stdout. Keep its real-harness qualification when upgrading the toolchain.
fn cases(v: &Value) -> Result<Vec<(String, String)>> {
    let simple = regex(&format!(r"\A(ok|failed|ignored) ({CASE})\z"));
    let ignored = regex(&format!(r"\Aignored: .* ({CASE})\z"));
    let mut cases = Vec::new();
    let mut seen = BTreeSet::new();
    for line in strings(v)? {
        let (name, outcome) = if let Some(m) = simple.captures(line) {
            (
                m[2].to_owned(),
                if &m[1] == "failed" {
                    "FAILED".into()
                } else {
                    m[1].to_owned()
                },
            )
        } else if let Some(m) = ignored.captures(line) {
            (m[1].to_owned(), "ignored".into())
        } else {
            return Err("unrecognized_libtest_result");
        };
        if !seen.insert(name.clone()) {
            return Err("duplicate_executed_case");
        }
        cases.push((name, outcome));
    }
    Ok(cases)
}
fn verify(v: &Value) -> Result<Value> {
    let cases = cases(&v["result_lines"])?;
    let summary = regex(
        r"\Atest result: (ok|FAILED)\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored; ([0-9]+) measured; ([0-9]+) filtered out; finished in .+\z",
    );
    let lines = strings(&v["lines"])?;
    let summaries: Vec<_> = lines.iter().filter_map(|s| summary.captures(s)).collect();
    if summaries.len() != 1 {
        return Err("missing_or_ambiguous_libtest_summary");
    }
    let m = &summaries[0];
    let count = |i| {
        m.get(i)
            .unwrap()
            .as_str()
            .parse::<u64>()
            .map_err(|_| "selected_executed_mismatch")
    };
    let (passed, failed, skipped, measured) = (count(2)?, count(3)?, count(4)?, count(5)?);
    let executed: BTreeSet<_> = cases
        .iter()
        .filter(|(_, s)| s.as_str() != "ignored")
        .map(|(n, _)| n.as_str())
        .collect();
    let ignored: BTreeSet<_> = cases
        .iter()
        .filter(|(_, s)| s.as_str() == "ignored")
        .map(|(n, _)| n.as_str())
        .collect();
    if executed != strings(&v["expected"])?.into_iter().collect()
        || ignored != strings(&v["ignored"])?.into_iter().collect()
        || passed
            != cases
                .iter()
                .map(|(_, outcome)| outcome)
                .filter(|s| s.as_str() == "ok")
                .count() as u64
        || failed
            != cases
                .iter()
                .map(|(_, outcome)| outcome)
                .filter(|s| s.as_str() == "FAILED")
                .count() as u64
        || skipped != ignored.len() as u64
        || measured != 0
    {
        return Err("selected_executed_mismatch");
    }
    Ok(
        json!({"executed":executed,"ignored":ignored,"passed":passed,"failed":failed,"summary_status": &m[1]}),
    )
}
fn evaluate(op: &str, v: &Value) -> Result<Value> {
    match op {
        "selection" => selection(v),
        "listing" => listing(v),
        "case-results" => {
            let results: serde_json::Map<_, _> = cases(&v["lines"])?
                .into_iter()
                .map(|(name, outcome)| (name, json!(outcome)))
                .collect();
            Ok(json!(results))
        }
        "verify" => verify(v),
        // The generic streaming guard intentionally has no discovered roster.
        // Inventory callers additionally require exact cases via `verify`.
        "positive-summary" => {
            let r = regex(r"\Atest result: ok\. [1-9][0-9]* passed; 0 failed; ");
            Ok(json!(strings(&v["lines"])?.iter().any(|s| r.is_match(s))))
        }
        _ => Err("invalid_policy_operation"),
    }
}
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--build-identity"] {
        println!("{}", env!("MARTY_CI_EXECUTION_BUILD_IDENTITY"));
        return;
    }
    let mut bytes = Vec::new();
    let response = if args.len() != 1 {
        Err("invalid_policy_operation")
    } else if io::stdin().read_to_end(&mut bytes).is_err() {
        Err("invalid_policy_input")
    } else {
        serde_json::from_slice(&bytes)
            .map_err(|_| "invalid_policy_input")
            .and_then(|v| evaluate(&args[0], &v))
    };
    println!(
        "{}",
        match response {
            Ok(v) => json!({"ok":true,"value":v}),
            Err(e) => json!({"ok":false,"error":e}),
        }
    );
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_roster_and_summary_are_independent_requirements() {
        let mut v = json!({"lines":["test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s"],"result_lines":["ok happy"],"expected":["happy"],"ignored":[]});
        assert!(verify(&v).is_ok());
        v["result_lines"] = json!(["ok other"]);
        assert_eq!(verify(&v), Err("selected_executed_mismatch"));
        v["result_lines"] = json!(["ok happy", "ok happy"]);
        assert_eq!(verify(&v), Err("duplicate_executed_case"));
    }
    #[test]
    fn selection_keeps_explicit_ignored_mode_and_skip_policy() {
        assert_eq!(
            selection(&json!({"arguments":["--ignored","a","--skip","b"],"allow_skip":true}))
                .unwrap(),
            json!([["a", "--skip", "b"], "ignored"])
        );
        assert_eq!(
            selection(&json!({"arguments":["--ignored","--include-ignored"]})),
            Err("ambiguous_ignored_selection")
        );
    }
}
