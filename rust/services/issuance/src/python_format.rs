//! Unselected candidate for Python 3.12 named-string formatting.
//! No evaluation, runtime Python, URL policy, or corpus-result lookup.
//! Object attributes outside the explicitly modeled builtin metadata remain an
//! internal capability gap, never a fabricated Python AttributeError.

use crate::{
    lossless_json_tree::{JsonNode, JsonTree},
    python_text::PythonText,
    python_value::{representation_points, PythonValueNode, PythonValueView},
};
use mmf_config::numeric_config::PythonConfigInteger;
use std::fmt;
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PythonFormatErrorKind {
    KeyError,
    IndexError,
    ValueError,
    TypeError,
    AttributeError,
    UnmodeledCapability,
    ResourceFailure,
}

#[derive(Clone, Eq, PartialEq)]
pub struct PythonFormatError {
    kind: PythonFormatErrorKind,
    message: PythonText,
}

impl PythonFormatError {
    pub fn kind(&self) -> PythonFormatErrorKind {
        self.kind
    }
    pub fn message(&self) -> &PythonText {
        &self.message
    }
}
impl fmt::Debug for PythonFormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PythonFormatError")
            .field(&self.kind)
            .finish()
    }
}
impl fmt::Display for PythonFormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Python formatting failed ({:?})", self.kind)
    }
}
impl std::error::Error for PythonFormatError {}

type Result<T> = std::result::Result<T, PythonFormatError>;
fn text(points: impl IntoIterator<Item = u32>) -> PythonText {
    PythonText::from_codepoints(points).expect("existing Python codepoints")
}
fn points(value: &str) -> Vec<u32> {
    value.chars().map(u32::from).collect()
}
fn error(kind: PythonFormatErrorKind, message: impl Into<String>) -> PythonFormatError {
    PythonFormatError {
        kind,
        message: message.into().into(),
    }
}
fn invalid(message: &str) -> PythonFormatError {
    error(PythonFormatErrorKind::ValueError, message)
}
fn unmodeled() -> PythonFormatError {
    error(
        PythonFormatErrorKind::UnmodeledCapability,
        "Python object attribute capability is not yet qualified",
    )
}
fn resource() -> PythonFormatError {
    error(
        PythonFormatErrorKind::ResourceFailure,
        "Formatting allocation could not be represented or reserved",
    )
}

#[derive(Clone, Copy)]
struct ReprText<'a>(&'a [u32]);
impl PythonValueView for ReprText<'_> {
    fn truthy(self) -> bool {
        !self.0.is_empty()
    }
    fn view(self) -> PythonValueNode<Self> {
        PythonValueNode::Text(self.0.to_vec())
    }
}
fn repr(value: &[u32]) -> Vec<u32> {
    representation_points(ReprText(value))
}
fn ascii_repr(value: &[u32]) -> Vec<u32> {
    repr(value)
        .into_iter()
        .flat_map(|point| {
            if point <= 0x7f {
                vec![point]
            } else if point <= 0xff {
                points(&format!("\\x{point:02x}"))
            } else if point <= 0xffff {
                points(&format!("\\u{point:04x}"))
            } else {
                points(&format!("\\U{point:08x}"))
            }
        })
        .collect()
}

fn append(output: &mut Vec<u32>, value: &[u32]) -> Result<()> {
    let length = output
        .len()
        .checked_add(value.len())
        .filter(|v| *v <= isize::MAX as usize)
        .ok_or_else(resource)?;
    output
        .try_reserve(length - output.len())
        .map_err(|_| resource())?;
    output.extend_from_slice(value);
    Ok(())
}

// A one-codepoint MMF integer conversion shares its frozen Unicode decimal
// table. Signs, separators and surrounding whitespace cannot parse as a digit.
fn digit(point: u32) -> Option<usize> {
    let character = char::from_u32(point)?;
    let parsed = character.to_string().parse::<PythonConfigInteger>().ok()?;
    parsed.to_usize().filter(|value| *value < 10)
}
fn decimal(input: &[u32], cursor: &mut usize) -> Result<Option<usize>> {
    let begin = *cursor;
    let mut value = 0_usize;
    while let Some(next) = input.get(*cursor).and_then(|point| digit(*point)) {
        value = value
            .checked_mul(10)
            .and_then(|v| v.checked_add(next))
            .filter(|v| *v <= isize::MAX as usize)
            .ok_or_else(|| invalid("Too many decimal digits in format string"))?;
        *cursor += 1;
    }
    Ok((*cursor != begin).then_some(value))
}

#[derive(Clone, Copy)]
enum BuiltinType {
    Str,
    Type,
}
impl BuiltinType {
    fn name(self) -> &'static str {
        match self {
            Self::Str => "str",
            Self::Type => "type",
        }
    }
}
enum Object {
    Text(Vec<u32>),
    Type(BuiltinType),
}
fn known_attribute(owner: &str, name: Option<&str>) -> bool {
    static INVENTORY: OnceLock<JsonTree> = OnceLock::new();
    let inventory = INVENTORY.get_or_init(|| {
        JsonTree::from_json_bytes(include_bytes!(
            "../../../../contracts/python-string-attribute-inventory.json"
        ))
        .expect("frozen builtin attribute inventory")
    });
    let member = |id, name: &str| {
        let JsonNode::Object(fields) = inventory.node(id) else {
            panic!("frozen builtin inventory object required")
        };
        fields
            .iter()
            .find(|(key, _)| key.as_scalar() == Some(name))
            .map(|(_, id)| *id)
    };
    let owners = member(inventory.root(), "owners").expect("builtin inventory owners");
    let attributes = member(owners, owner).expect("builtin inventory owner");
    name.is_some_and(|name| member(attributes, name).is_some())
}
impl Object {
    fn string(&self) -> Vec<u32> {
        match self {
            Self::Text(value) => value.clone(),
            Self::Type(value) => points(&format!("<class '{}'>", value.name())),
        }
    }
    fn attribute(self, name: &[u32]) -> Result<Self> {
        let scalar: Option<String> = name.iter().map(|v| char::from_u32(*v)).collect();
        let (owner, prefix) = match &self {
            Self::Text(_) => ("str_instance", "'str' object has no attribute '"),
            Self::Type(BuiltinType::Str) => ("str_type", "type object 'str' has no attribute '"),
            Self::Type(BuiltinType::Type) => ("type_type", "type object 'type' has no attribute '"),
        };
        if !known_attribute(owner, scalar.as_deref()) {
            let mut message = points(prefix);
            append(&mut message, name)?;
            append(&mut message, &[39])?;
            return Err(PythonFormatError {
                kind: PythonFormatErrorKind::AttributeError,
                message: text(message),
            });
        }
        match (self, scalar.as_deref()) {
            (Self::Text(_), Some("__class__")) => Ok(Self::Type(BuiltinType::Str)),
            (Self::Type(_), Some("__class__")) => Ok(Self::Type(BuiltinType::Type)),
            (Self::Type(value), Some("__name__" | "__qualname__")) => {
                Ok(Self::Text(points(value.name())))
            }
            (Self::Type(_), Some("__module__")) => Ok(Self::Text(points("builtins"))),
            _ => Err(unmodeled()),
        }
    }
    fn item(self, name: &[u32]) -> Result<Self> {
        let Self::Text(value) = self else {
            return Err(unmodeled());
        };
        let mut end = 0;
        let Some(index) = decimal(name, &mut end)?.filter(|_| end == name.len()) else {
            return Err(error(
                PythonFormatErrorKind::TypeError,
                "string indices must be integers, not 'str'",
            ));
        };
        value
            .get(index)
            .copied()
            .map(|point| Self::Text(vec![point]))
            .ok_or_else(|| {
                error(
                    PythonFormatErrorKind::IndexError,
                    "string index out of range",
                )
            })
    }
}

fn lookup(name: &[u32], fields: &[(&str, PythonText)]) -> Result<Object> {
    let first_end = name
        .iter()
        .position(|v| matches!(*v, 46 | 91))
        .unwrap_or(name.len());
    let first = &name[..first_end];
    let mut decimal_end = 0;
    let index = decimal(first, &mut decimal_end)?;
    if first.is_empty() || (decimal_end == first.len() && index.is_some()) {
        return Err(error(
            PythonFormatErrorKind::IndexError,
            format!(
                "Replacement index {} out of range for positional args tuple",
                index.unwrap_or(0)
            ),
        ));
    }
    let mut value = fields
        .iter()
        .find(|(key, _)| key.chars().map(u32::from).eq(first.iter().copied()))
        .map(|(_, value)| Object::Text(value.codepoints().collect()))
        .ok_or_else(|| PythonFormatError {
            kind: PythonFormatErrorKind::KeyError,
            message: text(repr(first)),
        })?;
    let mut cursor = first_end;
    while cursor < name.len() {
        let mode = name[cursor];
        cursor += 1;
        let start = cursor;
        match mode {
            46 => {
                while cursor < name.len() && !matches!(name[cursor], 46 | 91) {
                    cursor += 1;
                }
                if start == cursor {
                    return Err(invalid("Empty attribute in format string"));
                }
                value = value.attribute(&name[start..cursor])?;
            }
            91 => {
                while cursor < name.len() && name[cursor] != 93 {
                    cursor += 1;
                }
                if cursor == name.len() {
                    return Err(invalid("Missing ']' in format string"));
                }
                if start == cursor {
                    return Err(invalid("Empty attribute in format string"));
                }
                value = value.item(&name[start..cursor])?;
                cursor += 1;
            }
            _ => {
                return Err(invalid(
                    "Only '.' or '[' may follow ']' in format field specifier",
                ))
            }
        }
    }
    Ok(value)
}

struct Field<'a> {
    name: &'a [u32],
    conversion: Option<u32>,
    spec: &'a [u32],
    expand: bool,
}
fn field<'a>(input: &'a [u32], cursor: &mut usize) -> Result<Field<'a>> {
    let start = *cursor;
    while let Some(point) = input.get(*cursor).copied() {
        if matches!(point, 33 | 58 | 125) {
            break;
        }
        if point == 123 {
            return Err(invalid("unexpected '{' in field name"));
        }
        *cursor += 1;
        if point == 91 {
            while *cursor < input.len() && input[*cursor] != 93 {
                *cursor += 1;
            }
            if *cursor < input.len() {
                *cursor += 1;
            }
        }
    }
    let name = &input[start..*cursor];
    let mut delimiter = input
        .get(*cursor)
        .copied()
        .ok_or_else(|| invalid("expected '}' before end of string"))?;
    *cursor += 1;
    let mut conversion = None;
    if delimiter == 33 {
        conversion = Some(
            *input
                .get(*cursor)
                .ok_or_else(|| invalid("end of string while looking for conversion specifier"))?,
        );
        *cursor += 1;
        delimiter = *input
            .get(*cursor)
            .ok_or_else(|| invalid("unmatched '{' in format spec"))?;
        *cursor += 1;
        if delimiter != 58 && delimiter != 125 {
            return Err(invalid("expected ':' after conversion specifier"));
        }
    }
    if delimiter == 125 {
        return Ok(Field {
            name,
            conversion,
            spec: &[],
            expand: false,
        });
    }
    let start = *cursor;
    let mut nesting = 1;
    let mut expand = false;
    while *cursor < input.len() {
        let point = input[*cursor];
        *cursor += 1;
        if point == 123 {
            nesting += 1;
            expand = true;
        }
        if point == 125 {
            nesting -= 1;
            if nesting == 0 {
                return Ok(Field {
                    name,
                    conversion,
                    spec: &input[start..*cursor - 1],
                    expand,
                });
            }
        }
    }
    Err(invalid("unmatched '{' in format spec"))
}

fn conversion(value: Object, code: Option<u32>) -> Result<Object> {
    match code {
        None | Some(0) => Ok(value),
        Some(115) => Ok(Object::Text(value.string())),
        Some(114 | 97) => {
            let representation = match value {
                Object::Text(value) => {
                    if code == Some(97) {
                        ascii_repr(&value)
                    } else {
                        repr(&value)
                    }
                }
                Object::Type(_) => value.string(),
            };
            Ok(Object::Text(representation))
        }
        Some(point) => {
            let rendered = if (33..127).contains(&point) {
                char::from_u32(point).unwrap().to_string()
            } else {
                format!("\\x{point:x}")
            };
            Err(invalid(&format!("Unknown conversion specifier {rendered}")))
        }
    }
}

fn aligned(point: u32) -> bool {
    matches!(point, 60 | 62 | 61 | 94)
}
fn string_format(value: &[u32], spec: &[u32]) -> Result<Vec<u32>> {
    if spec.is_empty() {
        return Ok(value.to_vec());
    }
    let mut cursor = 0;
    let (mut fill, mut align, mut explicit_fill) = (32, 60, false);
    if spec.len() >= 2 && aligned(spec[1]) {
        fill = spec[0];
        align = spec[1];
        explicit_fill = true;
        cursor = 2;
    } else if aligned(spec[0]) {
        align = spec[0];
        cursor = 1;
    }
    let sign = spec
        .get(cursor)
        .copied()
        .filter(|v| matches!(*v, 32 | 43 | 45));
    cursor += usize::from(sign.is_some());
    let negative_zero = spec.get(cursor) == Some(&122);
    cursor += usize::from(negative_zero);
    let alternate = spec.get(cursor) == Some(&35);
    cursor += usize::from(alternate);
    if !explicit_fill && spec.get(cursor) == Some(&48) {
        fill = 48;
        cursor += 1;
    }
    let width = decimal(spec, &mut cursor)?.unwrap_or(0);
    let grouping = spec.get(cursor).copied().filter(|v| matches!(*v, 44 | 95));
    cursor += usize::from(grouping.is_some());
    if grouping.is_some_and(|first| {
        spec.get(cursor)
            .is_some_and(|next| matches!(*next, 44 | 95) && *next != first)
    }) {
        return Err(invalid("Cannot specify both ',' and '_'."));
    }
    let precision = if spec.get(cursor) == Some(&46) {
        cursor += 1;
        Some(
            decimal(spec, &mut cursor)?
                .ok_or_else(|| invalid("Format specifier missing precision"))?,
        )
    } else {
        None
    };
    if spec.len() - cursor > 1 {
        let mut message = points("Invalid format specifier '");
        append(&mut message, spec)?;
        append(&mut message, &points("' for object of type 'str'"))?;
        return Err(PythonFormatError {
            kind: PythonFormatErrorKind::ValueError,
            message: text(message),
        });
    }
    let presentation = spec.get(cursor).copied().unwrap_or(115);
    if let Some(grouping) = grouping {
        // Grouping is validated before dispatching to the string formatter.
        if !(matches!(presentation, 100 | 101 | 102 | 103 | 69 | 70 | 71 | 37 | 0)
            || grouping == 95 && matches!(presentation, 98 | 111 | 120 | 88))
        {
            let mut message = points("Cannot specify '");
            append(&mut message, &[grouping])?;
            append(&mut message, &points("' with '"))?;
            let code = if (33..128).contains(&presentation) {
                vec![presentation]
            } else {
                points(&format!("\\x{presentation:x}"))
            };
            append(&mut message, &code)?;
            append(&mut message, &points("'."))?;
            return Err(PythonFormatError {
                kind: PythonFormatErrorKind::ValueError,
                message: text(message),
            });
        }
    }
    if presentation != 115 {
        let code = if (33..128).contains(&presentation) {
            char::from_u32(presentation).unwrap().to_string()
        } else {
            format!("\\x{presentation:x}")
        };
        return Err(invalid(&format!(
            "Unknown format code '{code}' for object of type 'str'"
        )));
    }
    if let Some(sign) = sign {
        return Err(invalid(if sign == 32 {
            "Space not allowed in string format specifier"
        } else {
            "Sign not allowed in string format specifier"
        }));
    }
    if negative_zero {
        return Err(invalid(
            "Negative zero coercion (z) not allowed in string format specifier",
        ));
    }
    if alternate {
        return Err(invalid(
            "Alternate form (#) not allowed in string format specifier",
        ));
    }
    if align == 61 {
        return Err(invalid(
            "'=' alignment not allowed in string format specifier",
        ));
    }
    let count = precision.map_or(value.len(), |v| value.len().min(v));
    let padding = width.saturating_sub(count);
    let left = match align {
        62 => padding,
        94 => padding / 2,
        _ => 0,
    };
    let length = count
        .checked_add(padding)
        .filter(|v| *v <= isize::MAX as usize)
        .ok_or_else(resource)?;
    let mut output = Vec::new();
    output.try_reserve_exact(length).map_err(|_| resource())?;
    output.resize(left, fill);
    output.extend_from_slice(&value[..count]);
    output.resize(length, fill);
    Ok(output)
}

fn expand(input: &[u32], fields: &[(&str, PythonText)], depth: u8) -> Result<Vec<u32>> {
    if depth == 0 {
        return Err(invalid("Max string recursion exceeded"));
    }
    let mut output = Vec::new();
    let mut cursor = 0;
    while cursor < input.len() {
        let point = input[cursor];
        cursor += 1;
        if !matches!(point, 123 | 125) {
            append(&mut output, &[point])?;
            continue;
        }
        if input.get(cursor) == Some(&point) {
            cursor += 1;
            append(&mut output, &[point])?;
            continue;
        }
        if point == 125 {
            return Err(invalid("Single '}' encountered in format string"));
        }
        if cursor == input.len() {
            return Err(invalid("Single '{' encountered in format string"));
        }
        let parsed = field(input, &mut cursor)?;
        let value = conversion(lookup(parsed.name, fields)?, parsed.conversion)?;
        let expanded;
        let spec = if parsed.expand {
            expanded = expand(parsed.spec, fields, depth - 1)?;
            expanded.as_slice()
        } else {
            parsed.spec
        };
        let formatted = match value {
            Object::Text(value) => string_format(&value, spec)?,
            Object::Type(_) if spec.is_empty() => value.string(),
            Object::Type(_) => {
                return Err(error(
                    PythonFormatErrorKind::TypeError,
                    "unsupported format string passed to type.__format__",
                ))
            }
        };
        append(&mut output, &formatted)?;
    }
    Ok(output)
}

pub fn format_named(template: &PythonText, fields: &[(&str, PythonText)]) -> Result<PythonText> {
    let input: Vec<_> = template.codepoints().collect();
    expand(&input, fields, 2).map(text)
}

#[cfg(test)]
#[path = "python_format_tests.rs"]
mod tests;
