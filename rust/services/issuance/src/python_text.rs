//! Lossless Python codepoint text, distinct from a UTF-16 sequence or Rust str.
//! Serialization policy belongs to the consumer: no implicit replacement,
//! surrogate-pair folding, escaping, or early rendering error occurs here.

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct PythonText(Repr);

#[derive(Debug, Eq, PartialEq)]
enum Repr {
    Scalar(String),
    NonScalar(Vec<u32>),
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct InvalidCodepoint(pub u32);

impl PythonText {
    fn push(&mut self, value: u32) -> Result<(), InvalidCodepoint> {
        if value > 0x10ffff {
            return Err(InvalidCodepoint(value));
        }
        match &mut self.0 {
            Repr::Scalar(text) => {
                if let Some(character) = char::from_u32(value) {
                    text.push(character);
                } else {
                    let mut points = text.chars().map(u32::from).collect::<Vec<_>>();
                    points.push(value);
                    self.0 = Repr::NonScalar(points);
                }
            }
            Repr::NonScalar(points) => points.push(value),
        }
        Ok(())
    }

    pub(crate) fn from_codepoints(
        values: impl IntoIterator<Item = u32>,
    ) -> Result<Self, InvalidCodepoint> {
        let mut result = Self(Repr::Scalar(String::new()));
        for value in values {
            result.push(value)?;
        }
        Ok(result)
    }

    /// Copy only the retained prefix of already-decoded text. Callers must
    /// finish decoding and observe decoder errors before truncating this text.
    /// Ordinary scalar input keeps the String
    /// fast path; allocating a codepoint vector is necessary only for surrogates.
    pub(crate) fn excerpt(
        values: impl IntoIterator<Item = u32>,
        limit: usize,
    ) -> Result<Self, InvalidCodepoint> {
        let mut values = values.into_iter();
        let mut result = Self::from_codepoints(values.by_ref().take(limit))?;
        if values.next().is_some() {
            result.push(u32::from('…'))?;
        }
        Ok(result)
    }

    /// Conversion is explicit and returns the original lossless value on
    /// failure. Callers cannot accidentally persist replacement characters.
    pub(crate) fn into_scalar(self) -> Result<String, Self> {
        match self {
            Self(Repr::Scalar(text)) => Ok(text),
            other => Err(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn points(text: &PythonText) -> Vec<u32> {
        match &text.0 {
            Repr::Scalar(text) => text.chars().map(u32::from).collect(),
            Repr::NonScalar(points) => points.clone(),
        }
    }

    #[test]
    fn frozen_python_text_preserves_excerpt_and_scalar_conversion_boundaries() {
        let frozen: Value = serde_json::from_str(include_str!(
            "../../../../contracts/canvas-utf7-boundary-oracle.json"
        ))
        .unwrap();
        let cases = frozen["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 39);
        let mut non_scalar = 0;
        for case in cases {
            let input = case["text"]["python_codepoints"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| u32::try_from(v.as_u64().unwrap()).unwrap());
            let excerpt = PythonText::excerpt(input, 1000).unwrap();
            assert_eq!(
                serde_json::to_value(points(&excerpt)).unwrap(),
                case["excerpt"]["body_excerpt"]["python_codepoints"],
                "{}",
                case["body_hex"]
            );
            let scalar = excerpt.into_scalar().is_ok();
            assert_eq!(scalar, case["rendering"].get("error_class").is_none());
            non_scalar += usize::from(!scalar);
        }
        assert_eq!(non_scalar, 14);
    }

    #[test]
    fn codepoints_are_not_utf16_units_and_conversion_does_not_destroy_text() {
        let text = PythonText::from_codepoints([0xd800, 0xdc00, 0x10000]).unwrap();
        let unchanged = text.into_scalar().unwrap_err();
        assert_eq!(points(&unchanged), [0xd800, 0xdc00, 0x10000]);
        assert_eq!(
            PythonText::from_codepoints([0x110000]),
            Err(InvalidCodepoint(0x110000))
        );
        assert_eq!(
            PythonText::excerpt([0, 0xffff, 0x10ffff], 3)
                .unwrap()
                .into_scalar()
                .unwrap(),
            "\0\u{ffff}\u{10ffff}"
        );
    }

    #[test]
    fn excerpt_counts_codepoints_and_only_observes_one_extra_item() {
        let mut consumed = 0;
        let input = [0x10000, 0xd800, 0xdc00].into_iter().inspect(|_| {
            consumed += 1;
        });
        assert_eq!(
            PythonText::excerpt(input, 1)
                .unwrap()
                .into_scalar()
                .unwrap(),
            "\u{10000}…"
        );
        assert_eq!(consumed, 2);
        assert_eq!(
            PythonText::excerpt([0xd800], 0)
                .unwrap()
                .into_scalar()
                .unwrap(),
            "…"
        );
        assert_eq!(
            PythonText::excerpt([], 0).unwrap().into_scalar().unwrap(),
            ""
        );
    }
}
