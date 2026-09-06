//! Parsed JSON uses an arena: child links never own another node. Parsing,
//! cloning and destruction therefore do not consume stack proportional to depth.
use crate::{lossless_json::NonScalarJson, python_text::PythonText};
use serde_json::{Map, Value};

#[derive(Clone, Debug, PartialEq)]
pub enum JsonNode {
    Scalar(Value),
    Text(PythonText),
    Float(f64),
    Array(Vec<usize>),
    Object(Vec<(PythonText, usize)>),
}

#[derive(Clone, Debug, PartialEq)]
pub struct JsonTree {
    nodes: Vec<JsonNode>,
    root: usize,
}

struct ScalarSlots(Vec<Option<Value>>);
impl std::ops::Deref for ScalarSlots {
    type Target = Vec<Option<Value>>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for ScalarSlots {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for ScalarSlots {
    fn drop(&mut self) {
        for value in self.0.iter_mut().filter_map(Option::take) {
            crate::owned_json_value::drop_value(value);
        }
    }
}

impl JsonTree {
    pub fn from_response_bytes(bytes: &[u8]) -> Option<Self> {
        crate::canvas_credentials_protocol::response_json::parse_tree(bytes)
    }
    /// Database JSON keeps literal arbitrary-precision numbers. The response
    /// parser's Python float coercion and integer digit limit do not apply here.
    pub fn from_json_bytes(bytes: &[u8]) -> Option<Self> {
        crate::canvas_credentials_protocol::response_json::parse_json_tree(bytes)
    }
    pub(crate) fn new(nodes: Vec<JsonNode>, root: usize) -> Self {
        Self { nodes, root }
    }

    pub fn root(&self) -> usize {
        self.root
    }
    pub fn node(&self, index: usize) -> &JsonNode {
        &self.nodes[index]
    }
    pub fn is_object(&self) -> bool {
        matches!(self.node(self.root), JsonNode::Object(_))
    }

    pub fn container_depth(&self) -> usize {
        let mut maximum = 0;
        let mut pending = vec![(self.root, 0)];
        while let Some((id, parent)) = pending.pop() {
            match self.node(id) {
                JsonNode::Array(children) => {
                    maximum = maximum.max(parent + 1);
                    pending.extend(children.iter().map(|id| (*id, parent + 1)));
                }
                JsonNode::Object(entries) => {
                    maximum = maximum.max(parent + 1);
                    pending.extend(entries.iter().map(|(_, id)| (*id, parent + 1)));
                }
                _ => (),
            }
        }
        maximum
    }

    /// Conversion is explicit; callers owning a deep serde Value must also
    /// handle that value's lifetime and subsequent operations stack-safely.
    pub fn to_scalar(&self, validation: bool, excerpt_root: bool) -> Result<Value, NonScalarJson> {
        enum Task {
            Visit(usize),
            Finish(usize),
        }
        let mut pending = vec![Task::Visit(self.root)];
        let mut values = ScalarSlots((0..self.nodes.len()).map(|_| None).collect());
        while let Some(task) = pending.pop() {
            let id = match task {
                Task::Visit(id) => {
                    pending.push(Task::Finish(id));
                    match self.node(id) {
                        JsonNode::Array(children) => {
                            pending.extend(children.iter().rev().map(|id| Task::Visit(*id)))
                        }
                        JsonNode::Object(entries) => {
                            pending.extend(entries.iter().rev().map(|(_, id)| Task::Visit(*id)))
                        }
                        _ => (),
                    }
                    continue;
                }
                Task::Finish(id) => id,
            };
            values[id] = Some(match self.node(id) {
                JsonNode::Scalar(value) => value.clone(),
                JsonNode::Text(text) => {
                    Value::String(text.as_scalar().ok_or(NonScalarJson)?.to_owned())
                }
                JsonNode::Float(value) => match serde_json::Number::from_f64(*value) {
                    Some(number) => Value::Number(number),
                    None if validation => Value::Null,
                    None => return Err(NonScalarJson),
                },
                JsonNode::Array(children) => Value::Array(
                    children
                        .iter()
                        .map(|id| values[*id].take().unwrap())
                        .collect(),
                ),
                JsonNode::Object(entries) => {
                    let mut output = Map::new();
                    for (key, child) in entries {
                        let key = if validation && excerpt_root && id == self.root {
                            key.codepoints()
                                .map(|point| {
                                    char::from_u32(point).map_or_else(
                                        || "\u{fffd}\u{fffd}\u{fffd}".to_owned(),
                                        |character| character.to_string(),
                                    )
                                })
                                .collect()
                        } else {
                            key.as_scalar().ok_or(NonScalarJson)?.to_owned()
                        };
                        crate::owned_json_value::OwnedJsonValue::insert_map(
                            &mut output,
                            key,
                            values[*child].take().unwrap(),
                        );
                    }
                    Value::Object(output)
                }
            });
        }
        Ok(values[self.root].take().unwrap())
    }

    /// Render strict scalar JSON with an explicit task stack. PostgreSQL's NUL
    /// restriction is a separate opt-in at its persistence boundary.
    pub fn raw_json(
        &self,
        postgres: bool,
    ) -> Result<Box<serde_json::value::RawValue>, NonScalarJson> {
        crate::lossless_json_write::tree(self, postgres)
    }
}
