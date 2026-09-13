//! Published CPython GB18030 mappings with its complete-input error consumption.
//! Four-byte ranges avoid enumerating the large pending-input state space.

const SOURCE: &str = include_str!("../../../../contracts/canvas-gb18030-codec.json");
const POINTER_COUNT: u32 = 126 * 10 * 126 * 10;

#[derive(serde::Deserialize)]
struct Frozen {
    schema: String,
    pointer_count: u32,
    pairs_zlib_base64: String,
    ranges: Vec<[u32; 3]>,
}

pub(super) struct Decoder {
    pairs: super::Pairs,
    ranges: Vec<[u32; 3]>,
}

impl Decoder {
    pub(super) fn new() -> Self {
        let frozen: Frozen = serde_json::from_str(SOURCE).expect("embedded GB18030 schema");
        assert_eq!(frozen.schema, "marty.canvas-gb18030-codec/v1");
        assert_eq!(frozen.pointer_count, POINTER_COUNT);
        let pairs = super::Pairs::new(&frozen.pairs_zlib_base64);
        let mut previous_end = 0;
        for &[start, end, scalar] in &frozen.ranges {
            assert!(previous_end <= start && start < end && end <= POINTER_COUNT);
            let last = scalar
                .checked_add(end - start - 1)
                .expect("GB18030 scalar range");
            assert!(char::from_u32(scalar).is_some() && char::from_u32(last).is_some());
            assert!(last < 0xd800 || scalar > 0xdfff);
            previous_end = end;
        }
        Self {
            pairs,
            ranges: frozen.ranges,
        }
    }

    fn four_byte_scalar(&self, bytes: &[u8]) -> Option<char> {
        if !(0x81..=0xfe).contains(&bytes[0])
            || !(0x81..=0xfe).contains(&bytes[2])
            || !bytes[3].is_ascii_digit()
        {
            return None;
        }
        let pointer = u32::from(bytes[0] - 0x81) * 12600
            + u32::from(bytes[1] - b'0') * 1260
            + u32::from(bytes[2] - 0x81) * 10
            + u32::from(bytes[3] - b'0');
        let index = self.ranges.partition_point(|range| range[1] <= pointer);
        let &[start, end, scalar] = self.ranges.get(index)?;
        (start <= pointer && pointer < end)
            .then(|| char::from_u32(scalar + pointer - start).unwrap())
    }

    pub(super) fn decode(&self, bytes: &[u8], strict: bool) -> Option<String> {
        super::decode_complete(
            bytes,
            strict,
            |bytes| {
                if bytes.get(1).is_some_and(u8::is_ascii_digit) {
                    4
                } else {
                    2
                }
            },
            |bytes| {
                if bytes.len() == 4 {
                    self.four_byte_scalar(bytes)
                } else {
                    self.pairs.scalar(bytes)
                }
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{assert_hashes, observe};
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn all_pairs_pointers_and_byte_class_sequences_match_published_decoders() {
        let frozen: serde_json::Value = serde_json::from_str(SOURCE).unwrap();
        let decoder = super::super::lookup("gb18030").unwrap();
        let mut short = [Sha256::new(), Sha256::new()];
        for first in 0..=255u8 {
            observe(decoder, &mut short, &[first]);
            for second in 0..=255u8 {
                observe(decoder, &mut short, &[first, second]);
            }
        }
        assert_hashes(short, &frozen, "short_hashes");
        let mut pointers = [Sha256::new(), Sha256::new()];
        for pointer in 0..POINTER_COUNT {
            observe(
                decoder,
                &mut pointers,
                &[
                    (pointer / 12600 + 0x81) as u8,
                    (pointer / 1260 % 10 + 0x30) as u8,
                    (pointer / 10 % 126 + 0x81) as u8,
                    (pointer % 10 + 0x30) as u8,
                ],
            );
        }
        assert_hashes(pointers, &frozen, "pointer_hashes");
        let representatives = frozen["representatives"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| u8::try_from(value.as_u64().unwrap()).unwrap())
            .collect::<Vec<_>>();
        let mut grid = [Sha256::new(), Sha256::new()];
        for width in 0..=4 {
            for index in 0..representatives.len().pow(width) {
                let mut remainder = index;
                let mut payload = vec![0; width as usize];
                for byte in payload.iter_mut().rev() {
                    *byte = representatives[remainder % representatives.len()];
                    remainder /= representatives.len();
                }
                observe(decoder, &mut grid, &payload);
            }
        }
        assert_hashes(grid, &frozen, "grid_hashes");
    }
}
