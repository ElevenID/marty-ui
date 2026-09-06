//! Complete response JSON byte parsing into lossless values. JSON byte encoding
//! detection is independent of Content-Type and of replacement text decoding.
use crate::lossless_json_tree::{JsonNode, JsonTree};
use crate::{lossless_json::LosslessJson, python_text::PythonText};
use serde_json::Value;
use std::collections::HashMap;

pub(super) fn parse(bytes: &[u8]) -> Option<LosslessJson> {
    parse_tree(bytes).map(|tree| LosslessJson::Parsed(std::sync::Arc::new(tree)))
}

pub(crate) fn parse_tree(bytes: &[u8]) -> Option<JsonTree> {
    parse_with_numbers(bytes, false)
}

pub(crate) fn parse_json_tree(bytes: &[u8]) -> Option<JsonTree> {
    parse_with_numbers(bytes, true)
}

fn parse_with_numbers(bytes: &[u8], literal_numbers: bool) -> Option<JsonTree> {
    let points = decode(bytes)?;
    let mut parser = Parser {
        points,
        position: 0,
        literal_numbers,
    };
    let value = parser.value()?;
    parser.space();
    (parser.position == parser.points.len()).then_some(value)
}

fn decode(bytes: &[u8]) -> Option<Vec<u32>> {
    let (width, little, skip) = if bytes.starts_with(&[0xff, 0xfe, 0, 0]) {
        (4, true, 4)
    } else if bytes.starts_with(&[0, 0, 0xfe, 0xff]) {
        (4, false, 4)
    } else if bytes.starts_with(&[0xff, 0xfe]) {
        (2, true, 2)
    } else if bytes.starts_with(&[0xfe, 0xff]) {
        (2, false, 2)
    } else if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        (1, false, 3)
    } else if bytes.len() >= 4 && bytes[0] == 0 {
        (if bytes[1] == 0 { 4 } else { 2 }, false, 0)
    } else if bytes.len() >= 4 && bytes[1] == 0 {
        (if bytes[2] == 0 && bytes[3] == 0 { 4 } else { 2 }, true, 0)
    } else if bytes.len() == 2 && bytes[0] == 0 {
        (2, false, 0)
    } else if bytes.len() == 2 && bytes[1] == 0 {
        (2, true, 0)
    } else {
        (1, false, 0)
    };
    let bytes = &bytes[skip..];
    if !bytes.len().is_multiple_of(width) {
        return None;
    }
    if width == 1 {
        return utf8_surrogatepass(bytes);
    }
    let mut units = bytes
        .chunks_exact(width)
        .map(|chunk| {
            chunk.iter().enumerate().fold(0u32, |value, (index, byte)| {
                value | (u32::from(*byte) << (8 * if little { index } else { width - index - 1 }))
            })
        })
        .peekable();
    let mut output = Vec::new();
    while let Some(mut point) = units.next() {
        if point > 0x10ffff {
            return None;
        }
        if width == 2 && (0xd800..=0xdbff).contains(&point) {
            if let Some(low) = units.next_if(|point| (0xdc00..=0xdfff).contains(point)) {
                point = 0x10000 + ((point - 0xd800) << 10) + low - 0xdc00;
            }
        }
        output.push(point);
    }
    Some(output)
}

fn utf8_surrogatepass(bytes: &[u8]) -> Option<Vec<u32>> {
    let mut output = Vec::new();
    let mut position = 0;
    while position < bytes.len() {
        let first = bytes[position];
        let (length, minimum, mut point) = match first {
            0..=0x7f => (1, 0, u32::from(first)),
            0xc2..=0xdf => (2, 0x80, u32::from(first & 0x1f)),
            0xe0..=0xef => (3, 0x800, u32::from(first & 0xf)),
            0xf0..=0xf4 => (4, 0x10000, u32::from(first & 7)),
            _ => return None,
        };
        for byte in bytes.get(position + 1..position + length)? {
            if byte & 0xc0 != 0x80 {
                return None;
            }
            point = (point << 6) | u32::from(byte & 0x3f);
        }
        if point < minimum || point > 0x10ffff {
            return None;
        }
        output.push(point);
        position += length;
    }
    Some(output)
}

struct Parser {
    points: Vec<u32>,
    position: usize,
    literal_numbers: bool,
}

impl Parser {
    fn peek(&self) -> Option<u32> {
        self.points.get(self.position).copied()
    }
    fn take(&mut self, expected: u32) -> bool {
        if self.peek() == Some(expected) {
            self.position += 1;
            true
        } else {
            false
        }
    }
    fn space(&mut self) {
        while matches!(self.peek(), Some(9 | 10 | 13 | 32)) {
            self.position += 1;
        }
    }
    fn keyword(&mut self, word: &str) -> Option<()> {
        for byte in word.bytes() {
            if !self.take(u32::from(byte)) {
                return None;
            }
        }
        Some(())
    }
    fn value(&mut self) -> Option<JsonTree> {
        enum Frame {
            Array(Vec<usize>),
            Object {
                entries: Vec<(PythonText, usize)>,
                positions: HashMap<PythonText, usize>,
                key: PythonText,
            },
        }
        let mut frames = Vec::new();
        let mut nodes = Vec::new();
        loop {
            self.space();
            let node = match self.peek()? {
                91 => {
                    self.position += 1;
                    self.space();
                    if self.take(93) {
                        JsonNode::Array(Vec::new())
                    } else {
                        frames.push(Frame::Array(Vec::new()));
                        continue;
                    }
                }
                123 => {
                    self.position += 1;
                    self.space();
                    if self.take(125) {
                        JsonNode::Object(Vec::new())
                    } else {
                        let key = self.object_key()?;
                        frames.push(Frame::Object {
                            entries: Vec::new(),
                            positions: HashMap::new(),
                            key,
                        });
                        continue;
                    }
                }
                34 => JsonNode::Text(self.string()?),
                116 => {
                    self.keyword("true")?;
                    JsonNode::Scalar(Value::Bool(true))
                }
                102 => {
                    self.keyword("false")?;
                    JsonNode::Scalar(Value::Bool(false))
                }
                110 => {
                    self.keyword("null")?;
                    JsonNode::Scalar(Value::Null)
                }
                78 if !self.literal_numbers => {
                    self.keyword("NaN")?;
                    JsonNode::Float(f64::NAN)
                }
                73 if !self.literal_numbers => {
                    self.keyword("Infinity")?;
                    JsonNode::Float(f64::INFINITY)
                }
                45 if !self.literal_numbers && self.points.get(self.position + 1) == Some(&73) => {
                    self.keyword("-Infinity")?;
                    JsonNode::Float(f64::NEG_INFINITY)
                }
                45 | 48..=57 => self.number()?,
                _ => return None,
            };
            let mut id = nodes.len();
            nodes.push(node);
            loop {
                let Some(frame) = frames.last_mut() else {
                    return Some(JsonTree::new(nodes, id));
                };
                self.space();
                let finished = match frame {
                    Frame::Array(children) => {
                        children.push(id);
                        if self.take(93) {
                            true
                        } else {
                            if !self.take(44) {
                                return None;
                            }
                            false
                        }
                    }
                    Frame::Object {
                        entries,
                        positions,
                        key,
                    } => {
                        let key = std::mem::take(key);
                        if let Some(index) = positions.get(&key).copied() {
                            entries[index] = (key, id);
                        } else {
                            positions.insert(key.clone(), entries.len());
                            entries.push((key, id));
                        }
                        if self.take(125) {
                            true
                        } else {
                            if !self.take(44) {
                                return None;
                            }
                            let Frame::Object { key, .. } = frame else {
                                unreachable!()
                            };
                            *key = self.object_key()?;
                            false
                        }
                    }
                };
                if !finished {
                    break;
                }
                let node = match frames.pop().unwrap() {
                    Frame::Array(children) => JsonNode::Array(children),
                    Frame::Object { entries, .. } => JsonNode::Object(entries),
                };
                id = nodes.len();
                nodes.push(node);
            }
        }
    }

    fn object_key(&mut self) -> Option<PythonText> {
        self.space();
        let key = self.string()?;
        self.space();
        self.take(58).then_some(key)
    }
    fn string(&mut self) -> Option<PythonText> {
        if !self.take(34) {
            return None;
        }
        let mut text = PythonText::default();
        loop {
            let point = self.peek()?;
            self.position += 1;
            match point {
                34 => return Some(text),
                0..=31 => return None,
                92 => {
                    let escaped = self.peek()?;
                    self.position += 1;
                    let value = match escaped {
                        34 | 47 | 92 => escaped,
                        98 => 8,
                        102 => 12,
                        110 => 10,
                        114 => 13,
                        116 => 9,
                        117 => {
                            let mut high = self.hex4()?;
                            if (0xd800..=0xdbff).contains(&high)
                                && self.points.get(self.position..self.position + 2)
                                    == Some(&[92, 117])
                            {
                                let saved = self.position;
                                self.position += 2;
                                match self.hex4() {
                                    Some(low) if (0xdc00..=0xdfff).contains(&low) => {
                                        high = 0x10000 + ((high - 0xd800) << 10) + low - 0xdc00
                                    }
                                    _ => self.position = saved,
                                }
                            }
                            high
                        }
                        _ => return None,
                    };
                    text.push(value).ok()?;
                }
                _ => text.push(point).ok()?,
            }
        }
    }
    fn hex4(&mut self) -> Option<u32> {
        let mut value = 0;
        for _ in 0..4 {
            let point = self.peek()?;
            let digit = match point {
                48..=57 => point - 48,
                65..=70 => point - 55,
                97..=102 => point - 87,
                _ => return None,
            };
            self.position += 1;
            value = value * 16 + digit;
        }
        Some(value)
    }
    fn number(&mut self) -> Option<JsonNode> {
        let start = self.position;
        self.take(45);
        let digits = self.position;
        if !self.take(48) {
            if !matches!(self.peek(), Some(49..=57)) {
                return None;
            }
            while matches!(self.peek(), Some(48..=57)) {
                self.position += 1;
            }
        }
        let integer_digits = self.position - digits;
        let mut float = false;
        if self.take(46) {
            float = true;
            let before = self.position;
            while matches!(self.peek(), Some(48..=57)) {
                self.position += 1;
            }
            if self.position == before {
                return None;
            }
        }
        if self.take(101) || self.take(69) {
            float = true;
            if !self.take(43) {
                self.take(45);
            }
            let before = self.position;
            while matches!(self.peek(), Some(48..=57)) {
                self.position += 1;
            }
            if self.position == before {
                return None;
            }
        }
        let token: String = self.points[start..self.position]
            .iter()
            .map(|point| char::from_u32(*point).unwrap())
            .collect();
        if self.literal_numbers {
            return Some(JsonNode::Scalar(serde_json::from_str(&token).ok()?));
        }
        if float {
            return Some(JsonNode::Float(token.parse().ok()?));
        }
        if integer_digits > 4300 {
            return None;
        }
        // Arbitrary-precision serde numbers retain valid Python integers; -0 is
        // Python's integer zero, unlike floating-point negative zero.
        let token = if token == "-0" { "0" } else { &token };
        Some(JsonNode::Scalar(serde_json::from_str(token).ok()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn grammar_requires_a_complete_single_json_value() {
        for invalid in [
            "",
            " ",
            "+1",
            "01",
            "-01",
            "-",
            ".1",
            "1.",
            "1e",
            "1e+",
            "1e-",
            "nan",
            "infinity",
            "-NaN",
            "True",
            "false false",
            "[1,]",
            "{\"a\":1,}",
            "{a:1}",
            "\"\\x41\"",
            "\"\\u12g4\"",
            "\"\\u123\"",
            "\"\n\"",
            "\u{a0}null",
        ] {
            assert!(parse(invalid.as_bytes()).is_none(), "{invalid:?}");
        }
        for valid in [
            "null",
            "true",
            "false",
            "0",
            "-0",
            "1.0",
            "-12.34e-5",
            "1E+2",
            "[1,true,null,{}]",
            "{\"a\": [\"\\b\\f\\n\\r\\t\\/\\\\\\\"\"]}",
            "\t\r\n [ ] ",
        ] {
            assert!(parse(valid.as_bytes()).is_some(), "{valid:?}");
        }
    }

    fn points(bytes: &[u8]) -> Vec<u32> {
        let tree = tree(bytes);
        match tree.node(tree.root()) {
            JsonNode::Text(text) => text.codepoints().collect(),
            other => panic!("expected text, received {other:?}"),
        }
    }

    fn tree(bytes: &[u8]) -> std::sync::Arc<JsonTree> {
        let LosslessJson::Parsed(tree) = parse(bytes).unwrap() else {
            panic!("expected parsed arena")
        };
        tree
    }

    #[test]
    fn escaped_pairs_combine_but_raw_utf8_surrogates_remain_distinct() {
        assert_eq!(points(br#""\uD800\uDC00""#), [0x10000]);
        assert_eq!(points(br#""\uD800x\uDC00""#), [0xd800, 120, 0xdc00]);
        assert_eq!(points(br#""\uD800\u0041""#), [0xd800, 65]);
        assert_eq!(
            points(&[34, 0xed, 0xa0, 0x80, 0xed, 0xb0, 0x80, 34]),
            [0xd800, 0xdc00]
        );
        assert!(parse(br#""\uD800\uZZZZ""#).is_none());
    }

    #[test]
    fn byte_decoding_preserves_surrogates_and_rejects_invalid_sequences() {
        for little in [false, true] {
            for width in [2, 4] {
                let encode = |values: &[u32]| {
                    values
                        .iter()
                        .flat_map(|value| {
                            (0..width).map(move |index| {
                                (value >> (8 * if little { index } else { width - index - 1 }))
                                    as u8
                            })
                        })
                        .collect::<Vec<_>>()
                };
                let mut bytes = encode(&[0xfeff]);
                bytes.extend(encode(&[34, 0xd800, 0xdc00, 34]));
                assert_eq!(
                    points(&bytes),
                    if width == 2 {
                        vec![0x10000]
                    } else {
                        vec![0xd800, 0xdc00]
                    }
                );
                let mut lone = encode(&[0xfeff]);
                lone.extend(encode(&[34, 0xd800, 34]));
                assert_eq!(points(&lone), [0xd800]);
                lone.pop();
                assert!(parse(&lone).is_none());
            }
        }
        for invalid in [
            vec![34, 0xc0, 0x80, 34],
            vec![34, 0xe0, 0x80, 0x80, 34],
            vec![34, 0xf4, 0x90, 0x80, 0x80, 34],
            vec![34, 0xe2, 0x82, 34],
            vec![0xff, 0xfe, 0, 0, 34, 0, 0, 0, 0, 0, 0x11, 0, 34, 0, 0, 0],
        ] {
            assert!(parse(&invalid).is_none(), "{invalid:?}");
        }
    }

    #[test]
    fn duplicate_keys_keep_original_position_and_last_value() {
        let tree = tree(br#"{"b":1,"a":2,"\u0062":3,"\ud800":4,"\ud800":5}"#);
        let JsonNode::Object(entries) = tree.node(tree.root()) else {
            panic!("expected object")
        };
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].0.as_scalar(), Some("b"));
        assert_eq!(tree.node(entries[0].1), &JsonNode::Scalar(json!(3)));
        assert_eq!(entries[1].0.as_scalar(), Some("a"));
        assert_eq!(entries[2].0.codepoints().collect::<Vec<_>>(), [0xd800]);
        assert_eq!(tree.node(entries[2].1), &JsonNode::Scalar(json!(5)));
    }

    #[test]
    fn integer_digit_limit_and_float_distinctions_are_preserved() {
        for sign in ["", "-"] {
            assert!(parse(format!("{sign}{}", "9".repeat(4300)).as_bytes()).is_some());
            assert!(parse(format!("{sign}{}", "9".repeat(4301)).as_bytes()).is_none());
        }
        assert_eq!(parse(b"-0").unwrap().to_scalar().unwrap(), json!(0));
        for (token, expected) in [
            ("Infinity", f64::INFINITY),
            ("-Infinity", f64::NEG_INFINITY),
            ("1e400", f64::INFINITY),
            ("-1e400", f64::NEG_INFINITY),
            ("-0.0", -0.0),
            ("-1e-400", -0.0),
        ] {
            let tree = tree(token.as_bytes());
            let JsonNode::Float(value) = tree.node(tree.root()) else {
                panic!("{token}")
            };
            assert_eq!(value.to_bits(), expected.to_bits(), "{token}");
        }
        let tree = tree(b"NaN");
        let JsonNode::Float(value) = tree.node(tree.root()) else {
            panic!("NaN")
        };
        assert!(value.is_nan());
    }

    #[test]
    fn deep_parse_clone_drop_and_strict_serialization_use_a_small_stack() {
        std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(|| {
                for depth in [126, 127, 128, 129, 255, 256, 1600, 2048] {
                    for (open, close) in [("[", "]"), ("{\"nested\":", "}")] {
                        let source = format!("{}0{}", open.repeat(depth), close.repeat(depth));
                        let parsed = tree(source.as_bytes());
                        assert_eq!(parsed.container_depth(), depth);
                        let cloned = parsed.clone();
                        assert_eq!(cloned.raw_json(false).unwrap().get(), source);
                        assert_eq!(cloned.raw_json(true).unwrap().get(), source);
                        drop(parsed);
                        drop(cloned);
                        assert!(parse(&source.as_bytes()[..source.len() - 1]).is_none());
                    }
                }
            })
            .unwrap()
            .join()
            .unwrap();
    }
}
