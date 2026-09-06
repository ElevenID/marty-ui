//! Streaming content decoding shared by all operation-response consumers.
//! The published HTTPX image supports gzip, deflate and identity, not Brotli.
use flate2::{Decompress, FlushDecompress, Status};

use crate::canvas_operation_http::CanvasOperationHttpError;

pub(crate) struct CanvasContentDecoder {
    inflater: Decompress,
    raw_fallback: bool,
    first_attempt: bool,
}

impl CanvasContentDecoder {
    pub fn from_headers(headers: &http::HeaderMap) -> Vec<Self> {
        let mut decoders = headers
            .get_all(http::header::CONTENT_ENCODING)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .filter_map(|value| match value.trim().to_ascii_lowercase().as_str() {
                "gzip" => Some(Self {
                    inflater: Decompress::new_gzip(15),
                    raw_fallback: false,
                    first_attempt: true,
                }),
                "deflate" => Some(Self {
                    inflater: Decompress::new(true),
                    raw_fallback: true,
                    first_attempt: true,
                }),
                // HTTPX ignores unknown/unsupported codings; identity is a no-op.
                _ => None,
            })
            .collect::<Vec<_>>();
        decoders.reverse();
        decoders
    }

    pub fn decode(&mut self, input: &[u8]) -> Result<Vec<u8>, CanvasOperationHttpError> {
        let first = std::mem::replace(&mut self.first_attempt, false);
        match self.inflate(input) {
            Err(_) if first && self.raw_fallback => {
                // The original owner retries raw DEFLATE only on the first
                // decode call, not after a later stream failure.
                self.inflater = Decompress::new(false);
                self.inflate(input)
            }
            result => result,
        }
    }

    fn inflate(&mut self, input: &[u8]) -> Result<Vec<u8>, CanvasOperationHttpError> {
        let mut output = Vec::new();
        let mut offset = 0;
        loop {
            let mut buffer = [0; 8192];
            let before_in = self.inflater.total_in();
            let before_out = self.inflater.total_out();
            let status = self
                .inflater
                .decompress(&input[offset..], &mut buffer, FlushDecompress::None)
                .map_err(|_| CanvasOperationHttpError::Decoding)?;
            let consumed = (self.inflater.total_in() - before_in) as usize;
            let produced = (self.inflater.total_out() - before_out) as usize;
            offset += consumed;
            output.extend_from_slice(&buffer[..produced]);
            // zlib's Python object leaves bytes after the first stream unused.
            // EOF does not require StreamEnd: published flush accepts a missing
            // trailer. HTTP framing/read completion is independently enforced.
            if status == Status::StreamEnd
                || (consumed == 0 && produced == 0)
                || (offset == input.len() && produced < buffer.len())
            {
                return Ok(output);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn compressed(input: &[u8], gzip: bool) -> Vec<u8> {
        if gzip {
            let mut writer =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            writer.write_all(input).unwrap();
            writer.finish().unwrap()
        } else {
            let mut writer =
                flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            writer.write_all(input).unwrap();
            writer.finish().unwrap()
        }
    }

    fn decoder(coding: &str) -> CanvasContentDecoder {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::CONTENT_ENCODING, coding.parse().unwrap());
        CanvasContentDecoder::from_headers(&headers).pop().unwrap()
    }

    #[test]
    fn streaming_decoding_preserves_small_chunks_and_output_larger_than_buffer() {
        let source = b"synthetic response ".repeat(2000);
        for gzip in [true, false] {
            let encoded = compressed(&source, gzip);
            for size in [1, 3, 8192] {
                let mut decoder = decoder(if gzip { "gzip" } else { "deflate" });
                let mut output = Vec::new();
                for chunk in encoded.chunks(size) {
                    output.extend(decoder.decode(chunk).unwrap());
                }
                output.extend(decoder.decode(&[]).unwrap());
                assert_eq!(output, source);
            }
        }
    }

    #[test]
    fn raw_deflate_fallback_is_only_available_on_first_decode_call() {
        let mut writer =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        writer.write_all(b"synthetic response").unwrap();
        let raw = writer.finish().unwrap();
        assert_eq!(
            decoder("deflate").decode(&raw).unwrap(),
            b"synthetic response"
        );
        let mut late = decoder("deflate");
        assert!(late.decode(&[]).unwrap().is_empty());
        assert_eq!(
            late.decode(&raw).unwrap_err(),
            CanvasOperationHttpError::Decoding
        );
    }

    #[test]
    fn gzip_checksum_failure_is_not_accepted_as_a_missing_trailer() {
        let encoded = compressed(b"synthetic response", true);
        let trailer = encoded.len() - 8;
        assert_eq!(
            decoder("gzip").decode(&encoded[..trailer]).unwrap(),
            b"synthetic response"
        );
        let mut damaged = encoded;
        damaged[trailer] ^= 1;
        assert_eq!(
            decoder("gzip").decode(&damaged).unwrap_err(),
            CanvasOperationHttpError::Decoding
        );
    }
}
