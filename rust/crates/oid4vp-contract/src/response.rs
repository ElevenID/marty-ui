//! Complete, bounded association of wallet response items with a frozen query.
//! This is transport validation only; a consumer must authenticate every token
//! and check the selected query against the authenticated document.

use std::collections::{BTreeMap, BTreeSet};

use serde::{
    de::{MapAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::Value;

use crate::{
    Oid4vpContractError, Oid4vpEvaluationTransportV1, QueryKind, MAX_QUERY_REQUIREMENTS,
    MAX_TOKENS, MAX_TOKEN_BYTES,
};

#[derive(Clone, Debug, PartialEq)]
pub struct AssociatedResponseToken {
    pub query_id: String,
    pub format: String,
    pub token: String,
    pub query: Value,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AssociatedOid4vpResponse {
    pub tokens: Vec<AssociatedResponseToken>,
    /// Counts actual response tokens, independently of later profile checks.
    pub presentation_count: usize,
}

impl Oid4vpEvaluationTransportV1 {
    pub fn associate_response(&self) -> Result<AssociatedOid4vpResponse, Oid4vpContractError> {
        self.validate_transport()?;
        match self.query_kind {
            QueryKind::Dcql => self.associate_dcql(),
            QueryKind::PresentationExchange => self.associate_pe(),
        }
    }

    fn associate_dcql(&self) -> Result<AssociatedOid4vpResponse, Oid4vpContractError> {
        if self.presentation_submission.is_some() {
            return Err(Oid4vpContractError::PresentationDefinitionMismatch);
        }
        let entries = self.query_document["credentials"]
            .as_array()
            .filter(|entries| !entries.is_empty() && entries.len() <= MAX_QUERY_REQUIREMENTS)
            .ok_or(Oid4vpContractError::InvalidQueryDocument)?;
        let mut queries = BTreeMap::new();
        for query in entries {
            let id = nonempty(&query["id"])?;
            nonempty(&query["format"])?;
            if queries.insert(id.to_owned(), query).is_some() {
                return Err(Oid4vpContractError::InvalidQueryDocument);
            }
        }
        let raw = self.vp_token_raw.trim();
        let mut response = if raw.starts_with('{') {
            serde_json::from_str::<UniqueTokenMap>(raw)
                .map_err(|_| Oid4vpContractError::Deserialization)?
                .0
        } else if queries.len() == 1 {
            let token = single_token(raw)?;
            BTreeMap::from([(
                queries.keys().next().expect("one query").clone(),
                vec![token],
            )])
        } else {
            return Err(Oid4vpContractError::QueryCoverageMismatch);
        };
        if response.keys().collect::<BTreeSet<_>>() != queries.keys().collect::<BTreeSet<_>>() {
            return Err(Oid4vpContractError::QueryCoverageMismatch);
        }
        let mut tokens = Vec::new();
        let mut distinct_tokens = BTreeSet::new();
        for (id, query) in queries {
            let values = response.remove(&id).expect("matching query IDs");
            if values.is_empty() {
                return Err(Oid4vpContractError::QueryCoverageMismatch);
            }
            for token in values {
                validate_token(&token)?;
                if !distinct_tokens.insert(token.clone()) || tokens.len() == MAX_TOKENS {
                    return Err(Oid4vpContractError::QueryCoverageMismatch);
                }
                tokens.push(AssociatedResponseToken {
                    query_id: id.clone(),
                    format: nonempty(&query["format"])?.into(),
                    token,
                    query: query.clone(),
                });
            }
        }
        Ok(AssociatedOid4vpResponse {
            presentation_count: tokens.len(),
            tokens,
        })
    }

    fn associate_pe(&self) -> Result<AssociatedOid4vpResponse, Oid4vpContractError> {
        let submission = self
            .compatible_presentation_submission()?
            .ok_or(Oid4vpContractError::PresentationDefinitionMismatch)?;
        if submission.id.is_empty()
            || Some(submission.definition_id.as_str()) != self.query_document["id"].as_str()
        {
            return Err(Oid4vpContractError::PresentationDefinitionMismatch);
        }
        let entries = self.query_document["input_descriptors"]
            .as_array()
            .filter(|entries| !entries.is_empty() && entries.len() <= MAX_QUERY_REQUIREMENTS)
            .ok_or(Oid4vpContractError::InvalidQueryDocument)?;
        let mut queries = BTreeMap::new();
        for query in entries {
            if queries
                .insert(nonempty(&query["id"])?.to_owned(), query)
                .is_some()
            {
                return Err(Oid4vpContractError::InvalidQueryDocument);
            }
        }
        let raw = self.vp_token_raw.trim();
        let array = raw.starts_with('[');
        let values: Vec<String> = if array {
            serde_json::from_str(raw).map_err(|_| Oid4vpContractError::Deserialization)?
        } else {
            vec![single_token(raw)?]
        };
        if values.is_empty()
            || values.len() > MAX_TOKENS
            || values.iter().collect::<BTreeSet<_>>().len() != values.len()
        {
            return Err(Oid4vpContractError::QueryCoverageMismatch);
        }
        for token in &values {
            validate_token(token)?;
        }
        let mut used = BTreeSet::new();
        let mut tokens = Vec::new();
        for descriptor in submission.descriptor_map {
            let query = queries
                .remove(&descriptor.id)
                .ok_or(Oid4vpContractError::QueryCoverageMismatch)?;
            // Nested JWT/JSON paths need authenticated envelope evidence. The
            // current native kernels expose one credential, so reject instead
            // of guessing a nested token from unauthenticated JSON.
            if descriptor.path_nested.is_some() {
                return Err(Oid4vpContractError::CredentialBindingMismatch);
            }
            let index = if !array && descriptor.path == "$" {
                0
            } else if array {
                let raw_index = descriptor
                    .path
                    .strip_prefix("$[")
                    .and_then(|value| value.strip_suffix(']'))
                    .ok_or(Oid4vpContractError::CredentialBindingMismatch)?;
                let index = raw_index
                    .parse::<usize>()
                    .map_err(|_| Oid4vpContractError::CredentialBindingMismatch)?;
                if raw_index != index.to_string() {
                    return Err(Oid4vpContractError::CredentialBindingMismatch);
                }
                index
            } else {
                return Err(Oid4vpContractError::CredentialBindingMismatch);
            };
            let token = values
                .get(index)
                .ok_or(Oid4vpContractError::CredentialBindingMismatch)?;
            if query
                .get("format")
                .and_then(Value::as_object)
                .is_none_or(|formats| !formats.contains_key(&descriptor.format))
            {
                return Err(Oid4vpContractError::CredentialBindingMismatch);
            }
            used.insert(index);
            tokens.push(AssociatedResponseToken {
                query_id: descriptor.id,
                format: descriptor.format,
                token: token.clone(),
                query: query.clone(),
            });
        }
        if !queries.is_empty() || used.len() != values.len() {
            return Err(Oid4vpContractError::QueryCoverageMismatch);
        }
        Ok(AssociatedOid4vpResponse {
            tokens,
            presentation_count: values.len(),
        })
    }
}

fn nonempty(value: &Value) -> Result<&str, Oid4vpContractError> {
    value
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or(Oid4vpContractError::InvalidQueryDocument)
}

fn validate_token(token: &str) -> Result<(), Oid4vpContractError> {
    if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
        Err(Oid4vpContractError::SizeLimit("vp_token"))
    } else {
        Ok(())
    }
}

fn single_token(raw: &str) -> Result<String, Oid4vpContractError> {
    if raw.starts_with('"') {
        serde_json::from_str(raw).map_err(|_| Oid4vpContractError::Deserialization)
    } else if raw.starts_with(['{', '[']) {
        Err(Oid4vpContractError::Deserialization)
    } else {
        Ok(raw.to_owned())
    }
}

struct UniqueTokenMap(BTreeMap<String, Vec<String>>);

impl<'de> Deserialize<'de> for UniqueTokenMap {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct MapVisitor;
        impl<'de> Visitor<'de> for MapVisitor {
            type Value = UniqueTokenMap;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a unique map of query IDs to token arrays")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut result = BTreeMap::new();
                while let Some((key, value)) = map.next_entry::<String, Vec<String>>()? {
                    if result.len() >= MAX_QUERY_REQUIREMENTS || result.insert(key, value).is_some()
                    {
                        return Err(serde::de::Error::custom("duplicate or excessive query IDs"));
                    }
                }
                Ok(UniqueTokenMap(result))
            }
        }
        deserializer.deserialize_map(MapVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest_query_document;
    use serde_json::json;

    fn transport(
        kind: QueryKind,
        query: Value,
        response: &str,
        submission: Option<Value>,
    ) -> Oid4vpEvaluationTransportV1 {
        Oid4vpEvaluationTransportV1 {
            query_kind: kind,
            query_digest: digest_query_document(&query).unwrap(),
            query_document: query,
            presentation_submission: submission,
            vp_token_raw: response.into(),
            verifier_client_id: "https://verifier.example".into(),
            request_nonce: "nonce".into(),
        }
    }

    #[test]
    fn dcql_retains_every_item_and_requires_exact_query_coverage() {
        let query = json!({"credentials":[{"id":"employee","format":"dc+sd-jwt"},{"id":"license","format":"dc+sd-jwt"}]});
        let valid = transport(
            QueryKind::Dcql,
            query.clone(),
            r#"{"employee":["employee.one~","employee.two~"],"license":["license.one~"]}"#,
            None,
        );
        let associated = valid.associate_response().unwrap();
        assert_eq!(associated.presentation_count, 3);
        assert_eq!(
            associated
                .tokens
                .iter()
                .map(|item| item.token.as_str())
                .collect::<Vec<_>>(),
            ["employee.one~", "employee.two~", "license.one~"]
        );
        for response in [
            r#"{"employee":["employee.one~"]}"#,
            r#"{"employee":["employee.one~"],"other":["license.one~"]}"#,
            r#"{"employee":["employee.one~"],"license":[]}"#,
            r#"{"employee":["employee.one~"],"employee":["substitute~"],"license":["license.one~"]}"#,
            r#"{"employee":["same.token~"],"license":["same.token~"]}"#,
            "single.token~",
        ] {
            assert!(
                transport(QueryKind::Dcql, query.clone(), response, None)
                    .associate_response()
                    .is_err(),
                "{response}"
            );
        }
    }

    #[test]
    fn pe_validates_definition_full_mapping_and_actual_response_paths() {
        let query = json!({"id":"definition","input_descriptors":[{"id":"employee","format":{"dc+sd-jwt":{}}},{"id":"license","format":{"dc+sd-jwt":{}}}]});
        let submission = json!({"id":"submission","definition_id":"definition","descriptor_map":[{"id":"employee","format":"dc+sd-jwt","path":"$[0]"},{"id":"license","format":"dc+sd-jwt","path":"$[1]"}]});
        let valid = transport(
            QueryKind::PresentationExchange,
            query.clone(),
            r#"["employee.token~","license.token~"]"#,
            Some(submission.clone()),
        );
        let associated = valid.associate_response().unwrap();
        assert_eq!(associated.presentation_count, 2);
        assert_eq!(associated.tokens[1].token, "license.token~");
        for mutate in 0..5 {
            let mut altered = valid.clone();
            let submission = altered.presentation_submission.as_mut().unwrap();
            match mutate {
                0 => submission["definition_id"] = json!("other"),
                1 => submission["descriptor_map"][1]["id"] = json!("employee"),
                2 => submission["descriptor_map"][1]["path"] = json!("$[0]"),
                3 => {
                    submission["descriptor_map"][0]["path_nested"] =
                        json!({"id":"employee","format":"dc+sd-jwt","path":"$.vc"})
                }
                _ => {
                    altered.vp_token_raw =
                        r#"["employee.token~","license.token~","unused.token~"]"#.into()
                }
            }
            assert!(altered.associate_response().is_err(), "mutation {mutate}");
        }
    }
}
