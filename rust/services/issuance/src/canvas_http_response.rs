//! Shared Canvas body limits and pagination parsing. HTTP status and timeout
//! policy stay at each provider; operation responses keep their owned driver.
use bytes::Bytes;
use serde_json::Value;
use std::future::Future;

pub(crate) trait CanvasResponseBody: Send {
    type Error;
    fn content_length(&self) -> Option<u64>;
    fn next_chunk(&mut self) -> impl Future<Output = Result<Option<Bytes>, Self::Error>> + Send;
}
impl CanvasResponseBody for reqwest::Response {
    type Error = reqwest::Error;
    fn content_length(&self) -> Option<u64> {
        self.content_length()
    }
    async fn next_chunk(&mut self) -> Result<Option<Bytes>, Self::Error> {
        self.chunk().await
    }
}
#[derive(Debug, PartialEq)]
pub(crate) enum BodyError<E> {
    Transport(E),
    TooLarge,
    MalformedJson,
}

pub(crate) async fn bounded_json<R: CanvasResponseBody>(
    mut response: R,
    maximum: usize,
) -> Result<Value, BodyError<R::Error>> {
    let length = response.content_length();
    if length.is_some_and(|n| n > maximum as u64) {
        return Err(BodyError::TooLarge);
    }
    let mut bytes = Vec::with_capacity(length.unwrap_or(0).min(maximum as u64) as usize);
    while let Some(chunk) = response.next_chunk().await.map_err(BodyError::Transport)? {
        if bytes.len().saturating_add(chunk.len()) > maximum {
            return Err(BodyError::TooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| BodyError::MalformedJson)
}

#[derive(Debug)]
pub(crate) struct LinkError;

pub(crate) fn catalog_next_link(headers: &reqwest::header::HeaderMap) -> Option<String> {
    headers
        .get_all(reqwest::header::LINK)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .find_map(|entry| {
            let (target, parameters) = entry.trim().split_once('>')?;
            let target = target.trim().strip_prefix('<')?;
            parameters
                .split(';')
                .map(str::trim)
                .any(|parameter| parameter == "rel=\"next\"" || parameter == "rel=next")
                .then(|| target.to_owned())
        })
}

pub(crate) fn strict_next_link(headers: &[String]) -> Result<Option<String>, LinkError> {
    let mut next = None;
    for header in headers {
        parse_link_header(header, &mut next)?;
    }
    Ok(next)
}

fn parse_link_header(header: &str, next: &mut Option<String>) -> Result<(), LinkError> {
    if header.is_empty() || !header.is_ascii() {
        return Err(LinkError);
    }
    let bytes = header.as_bytes();
    let mut cursor = 0;
    skip_optional_whitespace(bytes, &mut cursor);
    if cursor == bytes.len() {
        return Err(LinkError);
    }
    loop {
        if bytes.get(cursor) != Some(&b'<') {
            return Err(LinkError);
        }
        cursor += 1;
        let target_start = cursor;
        while bytes.get(cursor).is_some_and(|value| *value != b'>') {
            if bytes[cursor].is_ascii_whitespace() || matches!(bytes[cursor], b'<' | b'"' | b'\\') {
                return Err(LinkError);
            }
            cursor += 1;
        }
        if cursor == target_start || bytes.get(cursor) != Some(&b'>') {
            return Err(LinkError);
        }
        let target = &header[target_start..cursor];
        cursor += 1;
        let mut relations = None;

        loop {
            skip_optional_whitespace(bytes, &mut cursor);
            if cursor == bytes.len() || bytes[cursor] == b',' {
                break;
            }
            if bytes[cursor] != b';' {
                return Err(LinkError);
            }
            cursor += 1;
            skip_optional_whitespace(bytes, &mut cursor);
            let name_start = cursor;
            while bytes.get(cursor).is_some_and(|value| is_token(*value)) {
                cursor += 1;
            }
            if cursor == name_start {
                return Err(LinkError);
            }
            let name = &header[name_start..cursor];
            skip_optional_whitespace(bytes, &mut cursor);
            if bytes.get(cursor) != Some(&b'=') {
                return Err(LinkError);
            }
            cursor += 1;
            skip_optional_whitespace(bytes, &mut cursor);
            let value = parse_link_parameter_value(header, bytes, &mut cursor)?;
            if name.eq_ignore_ascii_case("rel") {
                if relations.is_some() {
                    return Err(LinkError);
                }
                let parsed = value
                    .split_ascii_whitespace()
                    .map(str::to_owned)
                    .collect::<Vec<_>>();
                if parsed.is_empty() {
                    return Err(LinkError);
                }
                relations = Some(parsed);
            }
        }

        if relations.is_some_and(|relations| {
            relations
                .iter()
                .any(|relation| relation.eq_ignore_ascii_case("next"))
        }) && next.replace(target.to_owned()).is_some()
        {
            return Err(LinkError);
        }

        skip_optional_whitespace(bytes, &mut cursor);
        if cursor == bytes.len() {
            return Ok(());
        }
        if bytes[cursor] != b',' {
            return Err(LinkError);
        }
        cursor += 1;
        skip_optional_whitespace(bytes, &mut cursor);
        if cursor == bytes.len() {
            return Err(LinkError);
        }
    }
}

fn parse_link_parameter_value(
    header: &str,
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<String, LinkError> {
    if bytes.get(*cursor) == Some(&b'"') {
        *cursor += 1;
        let mut output = String::new();
        loop {
            let Some(value) = bytes.get(*cursor).copied() else {
                return Err(LinkError);
            };
            *cursor += 1;
            match value {
                b'"' => return Ok(output),
                b'\\' => {
                    let Some(escaped) = bytes.get(*cursor).copied() else {
                        return Err(LinkError);
                    };
                    if escaped.is_ascii_control() && escaped != b'\t' {
                        return Err(LinkError);
                    }
                    output.push(char::from(escaped));
                    *cursor += 1;
                }
                value if value.is_ascii_control() && value != b'\t' => {
                    return Err(LinkError);
                }
                value => output.push(char::from(value)),
            }
        }
    }
    let start = *cursor;
    while bytes
        .get(*cursor)
        .is_some_and(|value| is_parameter_token(*value))
    {
        *cursor += 1;
    }
    if *cursor == start {
        return Err(LinkError);
    }
    Ok(header[start..*cursor].to_owned())
}

fn skip_optional_whitespace(bytes: &[u8], cursor: &mut usize) {
    while bytes
        .get(*cursor)
        .is_some_and(|value| matches!(value, b' ' | b'\t'))
    {
        *cursor += 1;
    }
}

fn is_token(value: u8) -> bool {
    value.is_ascii_alphanumeric()
        || matches!(
            value,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn is_parameter_token(value: u8) -> bool {
    value.is_ascii_alphanumeric()
        || matches!(
            value,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'/'
                | b':'
                | b'<'
                | b'='
                | b'>'
                | b'?'
                | b'@'
                | b'['
                | b']'
                | b'^'
                | b'_'
                | b'`'
                | b'{'
                | b'|'
                | b'}'
                | b'~'
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    struct Body {
        length: Option<u64>,
        chunks: VecDeque<Result<Bytes, &'static str>>,
    }
    impl CanvasResponseBody for Body {
        type Error = &'static str;
        fn content_length(&self) -> Option<u64> {
            self.length
        }
        async fn next_chunk(&mut self) -> Result<Option<Bytes>, Self::Error> {
            self.chunks.pop_front().transpose()
        }
    }
    #[tokio::test]
    async fn limits_apply_to_announced_and_actual_chunked_bytes_and_keep_transport_errors() {
        let body = |length, chunks: Vec<Result<Bytes, &'static str>>| Body {
            length,
            chunks: chunks.into(),
        };
        assert_eq!(
            bounded_json(body(Some(3), vec![]), 2).await,
            Err(BodyError::TooLarge)
        );
        assert_eq!(
            bounded_json(
                body(
                    None,
                    vec![Ok(Bytes::from_static(b"{}")), Ok(Bytes::from_static(b" "))]
                ),
                2
            )
            .await,
            Err(BodyError::TooLarge)
        );
        assert_eq!(
            bounded_json(body(None, vec![Err("read-timeout")]), 2).await,
            Err(BodyError::Transport("read-timeout"))
        );
        assert_eq!(
            bounded_json(
                body(
                    None,
                    vec![Ok(Bytes::from_static(b"{")), Ok(Bytes::from_static(b"}"))]
                ),
                2
            )
            .await
            .unwrap(),
            serde_json::json!({})
        );
        assert_eq!(
            bounded_json(body(None, vec![Ok(Bytes::from_static(b"{"))]), 2).await,
            Err(BodyError::MalformedJson)
        );
    }
}
