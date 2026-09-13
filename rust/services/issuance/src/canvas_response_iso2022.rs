//! One stateful decoder for the seven independently captured ISO-2022 variants.
use super::{multibyte::decompress, CanvasResponseTextError};
use std::{collections::BTreeMap, sync::OnceLock};

pub(super) const SOURCES: &[(&str, &str)] = &[
    (
        "iso2022_kr",
        include_str!("../../../../contracts/canvas-iso2022-codecs/iso2022_kr.json"),
    ),
    (
        "iso2022_jp",
        include_str!("../../../../contracts/canvas-iso2022-codecs/iso2022_jp.json"),
    ),
    (
        "iso2022_jp_1",
        include_str!("../../../../contracts/canvas-iso2022-codecs/iso2022_jp_1.json"),
    ),
    (
        "iso2022_jp_2",
        include_str!("../../../../contracts/canvas-iso2022-codecs/iso2022_jp_2.json"),
    ),
    (
        "iso2022_jp_2004",
        include_str!("../../../../contracts/canvas-iso2022-codecs/iso2022_jp_2004.json"),
    ),
    (
        "iso2022_jp_3",
        include_str!("../../../../contracts/canvas-iso2022-codecs/iso2022_jp_3.json"),
    ),
    (
        "iso2022_jp_ext",
        include_str!("../../../../contracts/canvas-iso2022-codecs/iso2022_jp_ext.json"),
    ),
];

#[derive(serde::Deserialize)]
struct FrozenSet {
    width: usize,
    indices_zlib_base64: String,
    outputs_zlib_base64: String,
    outputs_size: usize,
}

#[derive(serde::Deserialize)]
struct Frozen {
    schema: String,
    name: String,
    shift: bool,
    g2: bool,
    extension: bool,
    sets: BTreeMap<u8, FrozenSet>,
    g2_strict: BTreeMap<u8, Vec<serde_json::Value>>,
}

struct Set {
    width: usize,
    indices: Vec<u32>,
    outputs: Vec<Option<String>>,
}

enum G2Value {
    Text(String),
    Invalid,
    Internal,
}

pub(super) struct Codec {
    shift: bool,
    g2: bool,
    extension: bool,
    sets: BTreeMap<u8, Set>,
    g2_values: BTreeMap<u8, Vec<G2Value>>,
}

struct State {
    groups: [u8; 3],
    shifted: bool,
    throughout: bool,
}

fn escape_end(byte: u8) -> bool {
    byte.is_ascii_uppercase() || byte == b'@'
}

impl Codec {
    fn new(name: &str, source: &str) -> Self {
        let frozen: Frozen = serde_json::from_str(source).expect("embedded ISO-2022 schema");
        assert_eq!(frozen.schema, "marty.canvas-iso2022-codec/v1");
        assert_eq!(frozen.name, name);
        let sets = frozen
            .sets
            .into_iter()
            .map(|(mark, frozen)| {
                assert!((1..=2).contains(&frozen.width));
                let outputs: Vec<Option<String>> = serde_json::from_slice(&decompress(
                    &frozen.outputs_zlib_base64,
                    frozen.outputs_size,
                ))
                .expect("embedded ISO-2022 outputs");
                assert!(outputs
                    .iter()
                    .flatten()
                    .all(|value| (1..=2).contains(&value.chars().count())));
                let count = if frozen.width == 2 { 96 * 256 } else { 96 };
                let indices = decompress(&frozen.indices_zlib_base64, count * 4)
                    .chunks_exact(4)
                    .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
                    .collect::<Vec<_>>();
                assert!(indices
                    .iter()
                    .all(|index| (*index as usize) < outputs.len()));
                (
                    mark,
                    Set {
                        width: frozen.width,
                        indices,
                        outputs,
                    },
                )
            })
            .collect();
        let g2_values = frozen.g2_strict.into_iter().map(|(mark, values)| {
            assert_eq!(values.len(), 256);
            let values = values.into_iter().map(|value| match value {
                serde_json::Value::Null => G2Value::Invalid,
                serde_json::Value::String(text) => {
                    assert_eq!(text.chars().count(), 1);
                    G2Value::Text(text)
                }
                error => {
                    assert_eq!(error, serde_json::json!({"error_class":"RuntimeError","error":"internal codec error"}));
                    G2Value::Internal
                }
            }).collect();
            (mark, values)
        }).collect();
        Self {
            shift: frozen.shift,
            g2: frozen.g2,
            extension: frozen.extension,
            sets,
            g2_values,
        }
    }

    // Success consumes a designation; error consumes exactly the published span.
    fn designation(&self, bytes: &[u8], state: &mut State) -> Result<usize, Option<usize>> {
        let mut index = 1;
        let mut length = 0;
        while index < 16 {
            if index >= bytes.len() {
                return Err(None);
            }
            if escape_end(bytes[index]) {
                length = index + 1;
                break;
            }
            if self.extension && bytes.get(index..index + 2) == Some(b"&@") {
                index += 2;
            }
            index += 1;
        }
        let (group, mark) = match length {
            0 => return Err(Some(1)),
            3 if bytes[1] == b'$' => (0, bytes[2] | 128),
            3 => (
                match bytes[1] {
                    b'(' => 0,
                    b')' => 1,
                    b'.' if self.g2 => 2,
                    _ => return Err(Some(length)),
                },
                bytes[2],
            ),
            4 if bytes[1] == b'$' => (
                match bytes[2] {
                    b'(' => 0,
                    b')' => 1,
                    _ => return Err(Some(length)),
                },
                bytes[3] | 128,
            ),
            6 if self.extension && bytes[3..6] == [0x1b, b'$', b'B'] => (0, b'B' | 128),
            _ => return Err(Some(length)),
        };
        if mark != b'B' && !self.sets.contains_key(&mark) {
            return Err(Some(length));
        }
        state.groups[group] = mark;
        Ok(length)
    }

    pub(super) fn decode(
        &self,
        mut bytes: &[u8],
        strict: bool,
    ) -> Result<Option<String>, CanvasResponseTextError> {
        let mut output = String::new();
        let mut state = State {
            groups: [b'B'; 3],
            shifted: false,
            throughout: false,
        };
        while let Some(&first) = bytes.first() {
            if state.throughout {
                output.push(char::from(first));
                bytes = &bytes[1..];
                if escape_end(first) {
                    state.throughout = false;
                }
                continue;
            }
            let invalid = match first {
                0x1b => {
                    if bytes.len() < 2 {
                        bytes.len()
                    } else if b"()$.&".contains(&bytes[1]) {
                        match self.designation(bytes, &mut state) {
                            Ok(length) => {
                                bytes = &bytes[length..];
                                continue;
                            }
                            Err(Some(length)) => length,
                            Err(None) if !strict && bytes.len() > 8 => {
                                return Err(CanvasResponseTextError::PendingBufferOverflow)
                            }
                            Err(None) => bytes.len(),
                        }
                    } else if self.g2 && bytes[1] == b'N' {
                        if bytes.len() < 3 {
                            bytes.len()
                        } else {
                            match &self.g2_values[&state.groups[2]][usize::from(bytes[2])] {
                                G2Value::Text(text) => {
                                    output.push_str(text);
                                    bytes = &bytes[3..];
                                    continue;
                                }
                                G2Value::Internal => {
                                    return Err(CanvasResponseTextError::InternalCodec)
                                }
                                G2Value::Invalid => 3,
                            }
                        }
                    } else {
                        output.push('\u{1b}');
                        state.throughout = true;
                        bytes = &bytes[1..];
                        continue;
                    }
                }
                0x0e | 0x0f if self.shift => {
                    state.shifted = first == 0x0e;
                    bytes = &bytes[1..];
                    continue;
                }
                0x0a => {
                    state.shifted = false;
                    output.push('\n');
                    bytes = &bytes[1..];
                    continue;
                }
                0..=0x1f => {
                    output.push(char::from(first));
                    bytes = &bytes[1..];
                    continue;
                }
                0x80..=0xff => 1,
                _ => {
                    let mark = state.groups[usize::from(state.shifted)];
                    if mark == b'B' {
                        output.push(char::from(first));
                        bytes = &bytes[1..];
                        continue;
                    }
                    let set = &self.sets[&mark];
                    if bytes.len() < set.width {
                        bytes.len()
                    } else {
                        let index = usize::from(first - 32) * if set.width == 2 { 256 } else { 1 }
                            + if set.width == 2 {
                                usize::from(bytes[1])
                            } else {
                                0
                            };
                        if let Some(text) = &set.outputs[set.indices[index] as usize] {
                            output.push_str(text);
                            bytes = &bytes[set.width..];
                            continue;
                        }
                        set.width
                    }
                }
            };
            if strict {
                return Ok(None);
            }
            output.push('\u{fffd}');
            bytes = &bytes[invalid..];
        }
        Ok(Some(output))
    }
}

pub(super) fn lookup(name: &str) -> Option<&'static Codec> {
    if !SOURCES.iter().any(|(candidate, _)| *candidate == name) {
        return None;
    }
    static CODECS: OnceLock<BTreeMap<&'static str, Codec>> = OnceLock::new();
    CODECS
        .get_or_init(|| {
            SOURCES
                .iter()
                .map(|(name, source)| (*name, Codec::new(name, source)))
                .collect()
        })
        .get(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn observe(codec: &Codec, digests: &mut [Sha256; 2], payload: &[u8]) {
        for (digest, strict) in digests.iter_mut().zip([false, true]) {
            let value = match codec.decode(payload, strict) {
                Ok(value) => value,
                Err(error) => {
                    digest.update([2]);
                    // Python's frozen error framing sorts these keys.
                    Some(serde_json::json!({"error":error.to_string(), "error_class":error.diagnostic_class()}).to_string())
                }
            };
            super::super::multibyte::tests::record(digest, value);
        }
    }

    fn payloads(frozen: &serde_json::Value, key: &str) -> Vec<Vec<u8>> {
        frozen[key]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| hex::decode(value.as_str().unwrap()).unwrap())
            .collect()
    }

    fn assert_hashes(name: &str, digests: [Sha256; 2], frozen: &serde_json::Value, key: &str) {
        for (index, digest) in digests.into_iter().enumerate() {
            assert_eq!(
                hex::encode(digest.finalize()),
                frozen[key][index],
                "{name} {key} mode {index}"
            );
        }
    }

    #[test]
    fn all_designation_states_and_escape_boundaries_match_published_decoders() {
        assert_eq!(SOURCES.len(), 7);
        for (name, source) in SOURCES {
            let codec = lookup(name).unwrap();
            let frozen: serde_json::Value = serde_json::from_str(source).unwrap();
            let prefixes = payloads(&frozen, "prefixes");
            let mut states = [Sha256::new(), Sha256::new()];
            for prefix in &prefixes {
                observe(codec, &mut states, prefix);
                for first in 0..=255u8 {
                    let mut payload = prefix.clone();
                    payload.push(first);
                    observe(codec, &mut states, &payload);
                    for second in 0..=255u8 {
                        payload.push(second);
                        observe(codec, &mut states, &payload);
                        payload.pop();
                    }
                }
            }
            assert_hashes(name, states, &frozen, "state_hashes");
            let seeds = payloads(&frozen, "escape_seeds");
            let tails = payloads(&frozen, "tails");
            let mut escapes = [Sha256::new(), Sha256::new()];
            for prefix in &prefixes {
                for seed in &seeds {
                    for width in 0..=seed.len() {
                        observe(
                            codec,
                            &mut escapes,
                            &[prefix.as_slice(), &seed[..width]].concat(),
                        );
                    }
                    for position in 0..seed.len() {
                        for byte in 0..=255u8 {
                            let mut payload = seed.clone();
                            payload[position] = byte;
                            for tail in &tails {
                                observe(
                                    codec,
                                    &mut escapes,
                                    &[prefix.as_slice(), &payload, tail].concat(),
                                );
                            }
                        }
                    }
                }
                for header in b"()$.&" {
                    for middle in [b"!".as_slice(), b"\xff", b"&@", b"\x1b"] {
                        for count in 0..19 {
                            for tail in &tails {
                                observe(
                                    codec,
                                    &mut escapes,
                                    &[
                                        prefix.as_slice(),
                                        &[0x1b, *header],
                                        &middle.repeat(count),
                                        tail,
                                    ]
                                    .concat(),
                                );
                            }
                        }
                    }
                }
            }
            assert_hashes(name, escapes, &frozen, "escape_hashes");
        }
    }
}
