use std::collections::HashMap;

#[derive(Default)]
pub struct Config {
    pub m: HashMap<String,String>,
}

impl Config {
    pub fn get<T: AsRef<str>>(&self, k:T) -> Option<&String> {
        self.m.get(k.as_ref())
    }

    pub fn insert<S: Into<String>, T: Into<String>>(&mut self, k:S, v:T) -> Option<String> {
        self.m.insert(k.into(), v.into())
    }
}
