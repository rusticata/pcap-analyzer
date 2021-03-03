use rusticata::{RParser, Variant};
use serde_json::Value;

/// Helper trait to convert a Rusticata object to a json Value
pub trait ToJsonExt {
    fn to_json_value(&self) -> Value {
        Value::Null
    }
}

impl ToJsonExt for Variant<'_> {
    fn to_json_value(&self) -> Value {
        match self {
            Variant::Bool(b) => Value::Bool(*b),
            Variant::Bytes(b) => Value::String(format!("{:x?}", *b)),
            Variant::I16(num) => Value::Number((*num).into()),
            Variant::I32(num) => Value::Number((*num).into()),
            Variant::I64(num) => Value::Number((*num).into()),
            Variant::I8(num) => Value::Number((*num).into()),
            Variant::List(l) => {
                let v: Vec<_> = l.iter().map(|item| item.to_json_value()).collect();
                Value::Array(v)
            }
            Variant::OwnedStr(s) => Value::String(s.to_owned()),
            Variant::Str(s) => Value::String((*s).into()),
            Variant::U16(num) => Value::Number((*num).into()),
            Variant::U32(num) => Value::Number((*num).into()),
            Variant::U64(num) => Value::Number((*num).into()),
            Variant::U8(num) => Value::Number((*num).into()),
            Variant::USize(num) => Value::Number((*num).into()),
        }
    }
}

impl ToJsonExt for Option<Variant<'_>> {
    fn to_json_value(&self) -> Value {
        match self {
            Some(v) => v.to_json_value(),
            None => Value::Null,
        }
    }
}

impl ToJsonExt for dyn RParser {
    fn to_json_value(&self) -> Value {
        let js = self
            .keys()
            .map(|&s| (s.to_owned(), self.get(s).to_json_value()))
            .collect();
        Value::Object(js)
    }
}
