//! Published EUC-KR pairs and eight-byte Hangul make-up sequences.

const SOURCE: &str = include_str!("../../../../contracts/canvas-euc-kr-codec.json");

#[derive(serde::Deserialize)]
struct Frozen {
    schema: String,
    pairs_zlib_base64: String,
    base_scalar: u32,
    components: [Vec<Option<u32>>; 3],
}

pub(super) struct Decoder {
    pairs: super::Pairs,
    components: [Vec<Option<u32>>; 3],
    base_scalar: u32,
}

impl Decoder {
    pub(super) fn new() -> Self {
        let frozen: Frozen = serde_json::from_str(SOURCE).expect("embedded EUC-KR schema");
        assert_eq!(frozen.schema, "marty.canvas-euc-kr-codec/v1");
        assert_eq!(frozen.base_scalar, 0xac00);
        for (row, (count, stride)) in frozen.components.iter().zip([(19, 588), (21, 28), (28, 1)]) {
            assert_eq!(row.len(), 256);
            let mut offsets = row.iter().flatten().copied().collect::<Vec<_>>();
            offsets.sort_unstable();
            assert_eq!(
                offsets,
                (0..count).map(|index| index * stride).collect::<Vec<_>>()
            );
        }
        Self {
            pairs: super::Pairs::new(&frozen.pairs_zlib_base64),
            components: frozen.components,
            base_scalar: frozen.base_scalar,
        }
    }

    fn scalar(&self, bytes: &[u8]) -> Option<char> {
        if bytes.len() == 2 {
            return self.pairs.scalar(bytes);
        }
        if [bytes[2], bytes[4], bytes[6]] != [0xa4; 3] {
            return None;
        }
        let scalar = self.base_scalar
            + self.components[0][usize::from(bytes[3])]?
            + self.components[1][usize::from(bytes[5])]?
            + self.components[2][usize::from(bytes[7])]?;
        char::from_u32(scalar)
    }

    pub(super) fn decode(&self, bytes: &[u8], strict: bool) -> Option<String> {
        super::decode_complete(
            bytes,
            strict,
            |bytes| {
                if bytes.starts_with(&[0xa4, 0xd4]) {
                    8
                } else {
                    2
                }
            },
            |bytes| self.scalar(bytes),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{assert_hashes, observe};
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn every_component_combination_and_mutated_prefix_matches_published_decoders() {
        let frozen: serde_json::Value = serde_json::from_str(SOURCE).unwrap();
        let decoder = super::super::lookup("euc_kr").unwrap();
        let mut short = [Sha256::new(), Sha256::new()];
        for first in 0..=255u8 {
            observe(decoder, &mut short, &[first]);
            for second in 0..=255u8 {
                observe(decoder, &mut short, &[first, second]);
            }
        }
        assert_hashes(short, &frozen, "short_hashes");
        let baseline = [0xa4, 0xd4, 0xa4, 0xa1, 0xa4, 0xbf, 0xa4, 0xd4];
        let mut components = [Sha256::new(), Sha256::new()];
        observe(decoder, &mut components, &baseline);
        for position in [3, 5, 7] {
            for byte in 0..=255u8 {
                let mut payload = baseline;
                payload[position] = byte;
                observe(decoder, &mut components, &payload);
            }
        }
        assert_hashes(components, &frozen, "component_hashes");
        let mut compositions = [Sha256::new(), Sha256::new()];
        for first in 0..=255u8 {
            for middle in 0..=255u8 {
                for final_byte in 0..=255u8 {
                    observe(
                        decoder,
                        &mut compositions,
                        &[0xa4, 0xd4, 0xa4, first, 0xa4, middle, 0xa4, final_byte],
                    );
                }
            }
        }
        assert_hashes(compositions, &frozen, "composition_hashes");
        let mut mutations = [Sha256::new(), Sha256::new()];
        for initial in frozen["mutation_bases"].as_array().unwrap() {
            let initial = hex::decode(initial.as_str().unwrap()).unwrap();
            for position in 0..8 {
                for byte in 0..=255u8 {
                    let mut payload = initial.clone();
                    payload[position] = byte;
                    for width in 0..=8 {
                        observe(decoder, &mut mutations, &payload[..width]);
                    }
                    for suffix in [b"A".as_slice(), &baseline, &[0xa4, 0xd4]] {
                        let mut extended = payload.clone();
                        extended.extend_from_slice(suffix);
                        observe(decoder, &mut mutations, &extended);
                    }
                }
            }
        }
        assert_hashes(mutations, &frozen, "mutation_hashes");
    }
}
