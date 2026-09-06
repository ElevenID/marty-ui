//! Complete-input UTF-7 decoding into lossless Python codepoints.
//! Strict and replacement modes share one implementation; response-body
//! adoption remains a separate consumer gate.
use crate::python_text::PythonText;

#[derive(Debug, Eq, PartialEq)]
pub(super) struct DecodeError {
    start: usize,
    end: usize,
    reason: &'static str,
}

fn sextet(byte: u8) -> Option<u32> {
    Some(u32::from(match byte {
        b'A'..=b'Z' => byte - b'A',
        b'a'..=b'z' => byte - b'a' + 26,
        b'0'..=b'9' => byte - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    }))
}

fn emit(output: &mut PythonText, point: u32) {
    output
        .push(point)
        .expect("UTF-7 units and combined pairs are valid Python codepoints");
}

fn failure(
    output: &mut PythonText,
    strict: bool,
    start: usize,
    end: usize,
    reason: &'static str,
) -> Result<(), DecodeError> {
    if strict {
        Err(DecodeError { start, end, reason })
    } else {
        emit(output, 0xfffd);
        Ok(())
    }
}

pub(super) fn decode(bytes: &[u8], strict: bool) -> Result<PythonText, DecodeError> {
    let mut output = PythonText::default();
    let mut index = 0;
    while index < bytes.len() {
        let start = index;
        let byte = bytes[index];
        index += 1;
        if byte != b'+' {
            if byte.is_ascii() {
                emit(&mut output, u32::from(byte));
            } else {
                failure(
                    &mut output,
                    strict,
                    start,
                    index,
                    "unexpected special character",
                )?;
            }
            continue;
        }
        let Some(&next) = bytes.get(index) else {
            // A final shift marker with no payload is accepted by the owner.
            break;
        };
        if next == b'-' {
            emit(&mut output, u32::from(b'+'));
            index += 1;
            continue;
        }
        if sextet(next).is_none() {
            index += 1;
            failure(&mut output, strict, start, index, "ill-formed sequence")?;
            continue;
        }

        let (mut pending_high, mut bits, mut buffer): (Option<u32>, u32, u32) = (None, 0, 0);
        while let Some(value) = bytes.get(index).copied().and_then(sextet) {
            buffer = (buffer << 6) | value;
            bits += 6;
            index += 1;
            if bits < 16 {
                continue;
            }
            bits -= 16;
            let unit = buffer >> bits;
            buffer &= (1 << bits) - 1;
            if let Some(high) = pending_high.take() {
                if (0xdc00..=0xdfff).contains(&unit) {
                    emit(
                        &mut output,
                        0x10000_u32 + ((high - 0xd800_u32) << 10) + unit - 0xdc00_u32,
                    );
                    continue;
                }
                emit(&mut output, high);
            }
            if (0xd800..=0xdbff).contains(&unit) {
                pending_high = Some(unit);
            } else {
                emit(&mut output, unit);
            }
        }
        if index == bytes.len() {
            if pending_high.is_some() || bits >= 6 || buffer != 0 {
                failure(
                    &mut output,
                    strict,
                    start,
                    index,
                    "unterminated shift sequence",
                )?;
            }
        } else if bits >= 6 || buffer != 0 {
            // A malformed shifted group consumes its terminator as part of the
            // error. Already emitted complete units are retained in replacement mode.
            index += 1;
            failure(
                &mut output,
                strict,
                start,
                index,
                if bits >= 6 {
                    "partial character in shift sequence"
                } else {
                    "non-zero padding bits in shift sequence"
                },
            )?;
        } else {
            let terminator = bytes[index];
            if terminator.is_ascii() {
                if let Some(high) = pending_high {
                    emit(&mut output, high);
                }
            }
            // Non-ASCII terminators are handled by the outer loop without
            // materializing a pending high surrogate; '-' alone is absorbed.
            if terminator == b'-' {
                index += 1;
            }
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};

    fn frozen() -> Value {
        serde_json::from_str(include_str!("../../../../contracts/canvas-utf7-codec.json")).unwrap()
    }

    fn observation(result: Result<PythonText, DecodeError>) -> Value {
        match result {
            Ok(text) => json!({"codepoints":text.codepoints().collect::<Vec<_>>()}),
            Err(error) => json!({"start":error.start,"end":error.end,"reason":error.reason}),
        }
    }

    fn shift(units: &[u16]) -> Vec<u8> {
        let bytes = units
            .iter()
            .flat_map(|unit| unit.to_be_bytes())
            .collect::<Vec<_>>();
        format!("+{}-", STANDARD_NO_PAD.encode(bytes)).into_bytes()
    }

    #[test]
    fn complete_text_and_strict_errors_match_independent_observations() {
        let source = frozen();
        assert_eq!(source["cases"].as_array().unwrap().len(), 134);
        for case in source["cases"].as_array().unwrap() {
            let bytes = hex::decode(case["body_hex"].as_str().unwrap()).unwrap();
            for (strict, mode) in [(false, "replacement"), (true, "strict")] {
                assert_eq!(
                    observation(decode(&bytes, strict)),
                    case[mode],
                    "{} {mode}",
                    case["body_hex"]
                );
            }
        }
        let boundary: Value = serde_json::from_str(include_str!(
            "../../../../contracts/canvas-utf7-boundary-oracle.json"
        ))
        .unwrap();
        for case in boundary["cases"].as_array().unwrap() {
            let bytes = hex::decode(case["body_hex"].as_str().unwrap()).unwrap();
            assert_eq!(
                observation(decode(&bytes, false))["codepoints"],
                case["text"]["python_codepoints"]
            );
        }
    }

    fn record(digest: &mut Sha256, result: Result<PythonText, DecodeError>) {
        match result {
            Ok(text) => {
                digest.update([1]);
                digest.update(
                    u32::try_from(text.codepoints().count())
                        .unwrap()
                        .to_le_bytes(),
                );
                for point in text.codepoints() {
                    digest.update(point.to_le_bytes());
                }
            }
            Err(error) => {
                digest.update([0]);
                for number in [error.start, error.end, error.reason.len()] {
                    digest.update(u32::try_from(number).unwrap().to_le_bytes());
                }
                digest.update(error.reason.as_bytes());
            }
        }
    }

    fn products(alphabet: &[u8], width: usize, input: &mut Vec<u8>, visit: &mut impl FnMut(&[u8])) {
        if width == 0 {
            visit(input);
            return;
        }
        for &byte in alphabet {
            input.push(byte);
            products(alphabet, width - 1, input, visit);
            input.pop();
        }
    }

    #[test]
    fn units_pairs_padding_terminators_and_raw_inputs_match_published_hashes() {
        let source = frozen();
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for group in [
            "short",
            "units",
            "pairs",
            "supplementary",
            "terminators",
            "grid",
        ] {
            let mut hashes = [Sha256::new(), Sha256::new()];
            let mut count = 0_u64;
            let mut visit = |bytes: &[u8]| {
                for (mode, digest) in hashes.iter_mut().enumerate() {
                    record(digest, decode(bytes, mode == 1));
                }
                count += 1;
            };
            match group {
                "short" => {
                    let values = (0..=255).collect::<Vec<u8>>();
                    for width in 0..3 {
                        products(&values, width, &mut Vec::new(), &mut visit);
                    }
                }
                "units" => {
                    for unit in 0..=u16::MAX {
                        let encoded = shift(&[unit]);
                        let mut bytes = encoded[..encoded.len() - 1].to_vec();
                        let last = alphabet.iter().position(|byte| *byte == bytes[3]).unwrap();
                        for padding in 0..4 {
                            bytes[3] = alphabet[last | padding];
                            visit(&bytes);
                            bytes.push(b'-');
                            visit(&bytes);
                            bytes.pop();
                        }
                    }
                }
                "pairs" => {
                    for special in source["special_units"].as_array().unwrap() {
                        let special = u16::try_from(special.as_u64().unwrap()).unwrap();
                        for unit in 0..=u16::MAX {
                            visit(&shift(&[special, unit]));
                            visit(&shift(&[unit, special]));
                        }
                    }
                }
                "supplementary" => {
                    for value in 0..0x100000_u32 {
                        visit(&shift(&[
                            (0xd800 + (value >> 10)) as u16,
                            (0xdc00 + (value & 1023)) as u16,
                        ]));
                    }
                }
                "terminators" => {
                    for seed in source["terminator_seeds_hex"].as_array().unwrap() {
                        let seed = hex::decode(seed.as_str().unwrap()).unwrap();
                        for byte in 0..=255 {
                            let mut input = vec![b'+'];
                            input.extend_from_slice(&seed);
                            input.push(byte);
                            input.extend_from_slice(b"tail");
                            visit(&input);
                        }
                    }
                }
                "grid" => {
                    let values = source["representatives"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| u8::try_from(v.as_u64().unwrap()).unwrap())
                        .collect::<Vec<_>>();
                    for width in 0..6 {
                        products(&values, width, &mut Vec::new(), &mut visit);
                    }
                }
                _ => unreachable!(),
            }
            assert_eq!(count, source["groups"][group]["count"].as_u64().unwrap());
            for (mode, digest) in hashes.into_iter().enumerate() {
                assert_eq!(
                    hex::encode(digest.finalize()),
                    source["groups"][group]["hashes"][mode].as_str().unwrap(),
                    "{group} mode {mode}"
                );
            }
        }
    }
}
