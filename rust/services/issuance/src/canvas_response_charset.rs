//! Published Content-Type parameter semantics, including RFC2231 continuations.
use super::{
    checked_encoding, response_codecs, unicode_units, CanvasResponseTextError, UnicodeEncoding,
};
use crate::python_text::PythonText;
use crate::python_value::strip;

struct Segment {
    number: Option<String>,
    value: String,
    encoded: bool,
}

fn unescape(value: &str) -> String {
    value.replace("\\\\", "\\").replace("\\\"", "\"")
}

fn unquote(value: &str) -> String {
    if let Some(inner) = value.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        unescape(inner)
    } else if let Some(inner) = value.strip_prefix('<').and_then(|s| s.strip_suffix('>')) {
        inner.to_owned()
    } else {
        value.to_owned()
    }
}

fn parameters(mut remaining: &str) -> Vec<(String, String)> {
    let mut parts = Vec::new();
    loop {
        let mut end = remaining.find(';').unwrap_or(remaining.len());
        // Preserve the published quote-counting behavior, including escaped
        // quotes preceded by more than one backslash.
        while end > 0
            && end < remaining.len()
            && !(remaining[..end].matches('"').count() - remaining[..end].matches("\\\"").count())
                .is_multiple_of(2)
        {
            end = remaining[end + 1..]
                .find(';')
                .map_or(remaining.len(), |i| end + 1 + i);
        }
        let field = strip(&remaining[..end]);
        let (name, value) = match field.split_once('=') {
            Some((name, value)) => (strip(name).to_lowercase(), strip(value).to_owned()),
            None => (field.to_owned(), String::new()),
        };
        parts.push((name, value));
        if end == remaining.len() {
            break;
        }
        remaining = &remaining[end + 1..];
    }
    parts
}

type Continuation<'a> = (&'a str, Option<String>, bool);

fn continuation(name: &str) -> Result<Option<Continuation<'_>>, CanvasResponseTextError> {
    let Some((base, suffix)) = name.split_once('*') else {
        return Ok(None);
    };
    if base.is_empty() || !base.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Ok(None);
    }
    if suffix.is_empty() {
        return Ok(Some((base, None, true)));
    }
    let digits = suffix.strip_suffix('*').unwrap_or(suffix);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Ok(None);
    }
    // The immutable published interpreter limits decimal conversions before
    // removing leading zeroes. Keep arbitrary-size ordering below that limit.
    if digits.len() > 4300 {
        return Err(CanvasResponseTextError::ContinuationOrdinalLimit {
            digits: digits.len(),
        });
    }
    // Decimal length + lexical ordering avoids an invented machine-integer cap.
    let number = digits.trim_start_matches('0');
    Ok(Some((
        base,
        Some(if number.is_empty() { "0" } else { number }.into()),
        name.ends_with('*'),
    )))
}

fn percent_octets(value: &str) -> String {
    let chars = value.chars().collect::<Vec<_>>();
    let mut output = String::new();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == '%' && index + 2 < chars.len() {
            if let (Some(a), Some(b)) =
                (chars[index + 1].to_digit(16), chars[index + 2].to_digit(16))
            {
                output.push(char::from((a * 16 + b) as u8));
                index += 3;
                continue;
            }
        }
        output.push(chars[index]);
        index += 1;
    }
    output
}

fn label_bytes(value: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for c in value.chars() {
        if u32::from(c) <= 255 {
            bytes.push(c as u8);
        } else if u32::from(c) <= 0xffff {
            bytes.extend_from_slice(format!("\\u{:04x}", u32::from(c)).as_bytes());
        } else {
            bytes.extend_from_slice(format!("\\U{:08x}", u32::from(c)).as_bytes());
        }
    }
    bytes
}

fn decode_label(
    value: &str,
    encoding: &str,
) -> Result<Option<PythonText>, CanvasResponseTextError> {
    let name = checked_encoding(encoding)?;
    if name == "utf_7" {
        return Ok(super::utf7::decode(&label_bytes(value), true).ok());
    }
    if let Some(codec) = super::iso2022::lookup(&name) {
        return codec
            .decode(&label_bytes(value), true)
            .map(|value| value.map(PythonText::from));
    }
    Ok(decode_basic_label(value, name).map(PythonText::from))
}

fn decode_basic_label(value: &str, name: String) -> Option<String> {
    let bytes = label_bytes(value);
    if name == "utf_8" || name == "utf_8_sig" {
        let data = if name == "utf_8_sig" {
            bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(&bytes)
        } else {
            &bytes
        };
        return std::str::from_utf8(data).ok().map(str::to_owned);
    }
    let registry = response_codecs();
    if let Some(machine) = super::multibyte::lookup(&name) {
        return machine.decode(&bytes, true);
    }
    if let Some(table) = registry.aliases.get(&name).map(|key| &registry.tables[key]) {
        return bytes
            .iter()
            .map(|byte| {
                let c = table[usize::from(*byte)];
                (c != char::REPLACEMENT_CHARACTER).then_some(c)
            })
            .collect();
    }
    use UnicodeEncoding::*;
    let (width, mut little, generic) = match registry.unicode_aliases.get(&name)? {
        Utf16 => (2, cfg!(target_endian = "little"), true),
        Utf16Le => (2, true, false),
        Utf16Be => (2, false, false),
        Utf32 => (4, cfg!(target_endian = "little"), true),
        Utf32Le => (4, true, false),
        Utf32Be => (4, false, false),
    };
    let mut data = bytes.as_slice();
    if generic {
        let (le, be): (&[u8], &[u8]) = if width == 2 {
            (&[0xff, 0xfe], &[0xfe, 0xff])
        } else {
            (&[0xff, 0xfe, 0, 0], &[0, 0, 0xfe, 0xff])
        };
        if data.starts_with(le) {
            little = true;
            data = &data[width..];
        } else if data.starts_with(be) {
            little = false;
            data = &data[width..];
        }
    }
    // Parameter labels use Python's strict, non-incremental decoding: generic
    // UTF16/32 without a BOM use native byte order, unlike response text.
    unicode_units(data, width, little, true)
}

pub(super) fn charset_parameter(
    content_type: &str,
) -> Result<Option<String>, CanvasResponseTextError> {
    let mut normal = Vec::new();
    let mut groups: Vec<(String, Vec<Segment>)> = Vec::new();
    for (index, (name, raw)) in parameters(content_type).into_iter().enumerate() {
        let value = unquote(&raw);
        if index > 0 {
            if let Some((base, number, encoded)) = continuation(&name)? {
                let position = groups
                    .iter()
                    .position(|(name, _)| name == base)
                    .unwrap_or_else(|| {
                        groups.push((base.to_owned(), Vec::new()));
                        groups.len() - 1
                    });
                groups[position].1.push(Segment {
                    number,
                    value,
                    encoded,
                });
                continue;
            }
        }
        normal.push((name, value));
    }
    let mut extended = Vec::new();
    for (name, mut segments) in groups {
        let numbered = segments[0].number.is_some();
        if let Some(other) = segments
            .iter()
            .find(|segment| segment.number.is_some() != numbered)
        {
            return Err(if other.number.is_some() {
                CanvasResponseTextError::NumberedAfterBareContinuation
            } else {
                CanvasResponseTextError::BareAfterNumberedContinuation
            });
        }
        segments.sort_by(|a, b| {
            match (&a.number, &b.number) {
                (Some(a), Some(b)) => a.len().cmp(&b.len()).then_with(|| a.cmp(b)),
                _ => std::cmp::Ordering::Equal,
            }
            .then_with(|| a.value.cmp(&b.value))
            .then_with(|| a.encoded.cmp(&b.encoded))
        });
        let encoded = segments.iter().any(|part| part.encoded);
        let joined = segments
            .into_iter()
            .map(|part| {
                if part.encoded {
                    percent_octets(&part.value)
                } else {
                    part.value
                }
            })
            .collect::<String>();
        if encoded {
            let quoted = joined.replace('\\', "\\\\").replace('"', "\\\"");
            let parts = quoted.splitn(3, '\'').collect::<Vec<_>>();
            let (encoding, value) = if parts.len() == 3 {
                (
                    if parts[0].is_empty() {
                        "us-ascii"
                    } else {
                        parts[0]
                    },
                    unescape(parts[2]),
                )
            } else {
                ("us-ascii", joined)
            };
            extended.push((name, Some(encoding.to_owned()), value));
        } else {
            extended.push((name, None, joined));
        }
    }
    // Decode every continuation group before selecting the first ordinary
    // charset; malformed unrelated groups can also raise in the published reader.
    let ordinary = normal
        .into_iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("charset"))
        .map(|(_, value)| value);
    let value = if ordinary.is_some() {
        ordinary
    } else if let Some((_, encoding, value)) = extended
        .into_iter()
        .find(|(name, _, _)| name.eq_ignore_ascii_case("charset"))
    {
        Some(match encoding {
            Some(encoding) => match decode_label(&value, &encoding)? {
                Some(text) => match text.into_scalar() {
                    Ok(text) => text,
                    // A successfully decoded non-scalar label fails the same
                    // final ASCII filter as non-ASCII scalar labels. It is not
                    // a strict decode failure that falls back to the raw value.
                    Err(_) => return Ok(None),
                },
                None => value,
            },
            None => value,
        })
    } else {
        None
    };
    Ok(value
        .filter(|s| s.is_ascii())
        .map(|s| s.to_ascii_lowercase()))
}
