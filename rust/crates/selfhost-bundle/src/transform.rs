//! Original packaging text rules, with separately governed safety validation.
use regex::Regex;
use serde_yaml::Value;

pub fn strip_build_blocks(input: &str) -> String {
    let mut lines = Vec::new();
    let mut skipping = false;
    for line in input.lines() {
        let stripped = line.trim_start();
        if skipping {
            if !stripped.is_empty() && line.len() - stripped.len() <= 4 {
                skipping = false;
            } else {
                continue;
            }
        }
        if line.starts_with("    build:") {
            skipping = true;
        } else {
            lines.push(line);
        }
    }
    format!("{}\n", lines.join("\n").trim_end())
}

/// Frozen legacy predicate; strict validation additionally checks interpolation defaults.
pub fn image_uses_mutable_tag(image: &str) -> bool {
    ["latest", "prod", "main", "dev"].iter().any(|tag| {
        image.ends_with(&format!(":{tag}"))
            || image.contains(&format!(":{tag}@"))
            || image.contains(&format!(":-${tag}"))
            || image.contains(&format!(":?{tag}"))
            || image.contains(&format!(":{tag}}}"))
    })
}

fn mutable_lines(text: &str) -> Vec<&str> {
    let image = Regex::new(r"^\s*image:\s*(\S+)").unwrap();
    let assignment = Regex::new(r"^\s*(?:SELFHOST_IMAGE_TAG|IMAGE_TAG)=([^#\s]+)").unwrap();
    text.lines()
        .filter(|line| {
            image
                .captures(line)
                .is_some_and(|capture| image_uses_mutable_tag(&capture[1]))
                || assignment.captures(line).is_some_and(|capture| {
                    ["latest", "prod", "main", "dev"]
                        .contains(&capture[1].to_ascii_lowercase().as_str())
                })
        })
        .map(str::trim)
        .collect()
}

pub fn validate_image_based_compose(text: &str) -> Result<(), String> {
    if Regex::new(r"(?m)^\s*build\s*:").unwrap().is_match(text) {
        return Err("Generated customer compose still contains build blocks; image-based bundles must not require source builds.".into());
    }
    let mutable = mutable_lines(text);
    if !mutable.is_empty() {
        return Err(format!("Generated customer compose contains mutable image tags; use immutable release tags only:\n  - {}", mutable.join("\n  - ")));
    }
    let mut missing = Vec::new();
    let mut in_services = false;
    let mut current: Option<(&str, bool)> = None;
    for line in text.lines() {
        let stripped = line.trim_start();
        let indent = line.len() - stripped.len();
        if indent == 0 {
            if stripped == "services:" {
                in_services = true;
                continue;
            }
            if in_services {
                break;
            }
        }
        if !in_services {
            continue;
        }
        if indent == 2 && stripped.ends_with(':') {
            if let Some((name, false)) = current.take() {
                missing.push(name);
            }
            current = Some((stripped.trim_end_matches(':'), false));
        } else if line.starts_with("    image:") {
            if let Some((_, seen)) = &mut current {
                *seen = true;
            }
        }
    }
    if let Some((name, false)) = current {
        missing.push(name);
    }
    missing.sort_unstable();
    if !missing.is_empty() {
        return Err(format!(
            "Generated customer compose services missing image declarations: {}",
            missing.join(", ")
        ));
    }
    Ok(())
}

fn image_variants(input: &str, depth: usize) -> Result<Vec<String>, String> {
    if depth > 64 {
        return Err("Image interpolation nesting exceeds the package limit".into());
    }
    let Some(start) = input.find("${") else {
        return Ok(vec![input.into()]);
    };
    let mut balance = 1;
    let mut end = None;
    for (offset, character) in input[start + 2..].char_indices() {
        match character {
            '{' => balance += 1,
            '}' => balance -= 1,
            _ => (),
        }
        if balance == 0 {
            end = Some(start + 2 + offset);
            break;
        }
    }
    let end = end.ok_or("Unclosed image interpolation")?;
    let expression = &input[start + 2..end];
    let variable_end = expression
        .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .unwrap_or(expression.len());
    let variable = &expression[..variable_end];
    if variable.is_empty() || variable.as_bytes()[0].is_ascii_digit() {
        return Err("Invalid image interpolation variable".into());
    }
    let operator = &expression[variable_end..];
    let unknown = "marty-required-operator-value".to_owned();
    let choices = if let Some(default) = operator
        .strip_prefix(":-")
        .or_else(|| operator.strip_prefix('-'))
    {
        let mut choices = image_variants(default, depth + 1)?;
        choices.push(unknown);
        choices
    } else if let Some(alternate) = operator
        .strip_prefix(":+")
        .or_else(|| operator.strip_prefix('+'))
    {
        let mut choices = image_variants(alternate, depth + 1)?;
        choices.push(String::new());
        choices
    } else if operator.is_empty() || operator.starts_with(":?") || operator.starts_with('?') {
        vec![unknown]
    } else {
        return Err("Invalid image interpolation operator".into());
    };
    let suffixes = image_variants(&input[end + 1..], depth + 1)?;
    if choices.len().saturating_mul(suffixes.len()) > 256 {
        return Err("Image interpolation alternatives exceed the package limit".into());
    }
    Ok(choices
        .into_iter()
        .flat_map(|choice| {
            suffixes
                .iter()
                .map(move |suffix| format!("{}{choice}{suffix}", &input[..start]))
        })
        .collect())
}

pub fn validate_strict(text: &str) -> Result<(), String> {
    validate_image_based_compose(text)?;
    let document: Value =
        serde_yaml::from_str(text).map_err(|_| "Generated compose is invalid YAML")?;
    let services = document
        .get("services")
        .and_then(Value::as_mapping)
        .filter(|map| !map.is_empty())
        .ok_or("Generated compose has no services")?;
    for service in services.values() {
        let image = service
            .get("image")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or("Generated service has no image")?;
        if service.get("build").is_some() || service.get("extends").is_some() {
            return Err("Generated service retains a build or source extends dependency".into());
        }
        if image_uses_mutable_tag(image)
            || image_variants(image, 0)?
                .iter()
                .any(|image| image_uses_mutable_tag(image))
        {
            return Err(
                "Generated image contains a mutable literal or interpolation default".into(),
            );
        }
    }
    Ok(())
}

pub fn validate_customer_text(text: &str) -> Result<(), String> {
    if Regex::new(r"(?m)^\s*build\s*:").unwrap().is_match(text) {
        return Err("Customer bundle contains build keys".into());
    }
    if !mutable_lines(text).is_empty() {
        return Err("Customer bundle contains mutable image tags".into());
    }
    Ok(())
}
