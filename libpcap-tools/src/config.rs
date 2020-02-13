use std::io;
use std::str::FromStr;

pub struct Config {
    value: toml::Value,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            value: toml::Value::Table(toml::map::Map::new()),
        }
    }
}

impl Config {
    fn get_value<T: AsRef<str>>(&self, k: T) -> Option<&toml::Value> {
        let mut item = &self.value;
        for key in k.as_ref().split('.') {
            item = item.get(key)?;
        }
        Some(item)
    }
    /// Get an entry by path. If the input argument contains dots, the path is split
    /// into keys, each key being requested recursively.
    pub fn get<T: AsRef<str>>(&self, k: T) -> Option<&str> {
        let item = self.get_value(k)?;
        item.as_str()
    }
    /// Get an entry of type integer by path
    pub fn get_usize<T: AsRef<str>>(&self, k: T) -> Option<usize> {
        let item = self.get_value(k)?;
        item.as_integer()
            .and_then(|i| if i >= 0 { Some(i as usize) } else { None })
    }
    /// Get an entry of type boolean by path
    pub fn get_bool<T: AsRef<str>>(&self, k: T) -> Option<bool> {
        let item = self.get_value(k)?;
        item.as_bool()
    }
    /// Add a new section at location path.
    /// To insert at root, use an empty path.
    pub fn add_section<T: AsRef<str>, V: ToString>(
        &mut self,
        parent: T,
        table_name: V,
    ) -> Option<()> {
        let mut item = &mut self.value;
        if !parent.as_ref().is_empty() {
            for key in parent.as_ref().split('.') {
                item = item.get_mut(key)?;
            }
        }
        if let Some(t) = item.as_table_mut() {
            t.insert(
                table_name.to_string(),
                toml::Value::Table(toml::map::Map::new()),
            );
            return Some(());
        }
        None
    }

    /// Set an entry by path. If the input argument contains dots, the path is split
    /// into keys, each key being requested recursively.
    /// Intermediate path elements must already exist
    pub fn set<T, V>(&mut self, k: T, v: V) -> Option<()>
    where
        T: AsRef<str>,
        toml::value::Value: std::convert::From<V>,
    {
        let mut item = &mut self.value;
        let path: Vec<_> = k.as_ref().split('.').collect();
        if path.len() > 1 {
            for key in path.iter().take(path.len() - 1) {
                item = item.get_mut(key)?;
            }
        }
        if let Some(t) = item.as_table_mut() {
            if let Some(p) = path.last() {
                t.insert((*p).to_string(), toml::Value::from(v));
                return Some(());
            }
        }
        None
    }

    /// Load configuration from input object. If keys are already present, they are overwritten
    pub fn load_config<R: io::Read>(&mut self, mut config: R) -> Result<(), io::Error> {
        let mut s = String::new();
        config.read_to_string(&mut s)?;
        match toml::Value::from_str(&s) {
            Ok(value) => {
                self.value = value;
                Ok(())
            }
            _ => Err(io::Error::new(
                io::ErrorKind::Other,
                "Load configuration failed",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Config;
    #[test]
    fn config_add_values() {
        let mut config = Config::default();
        let res = config.set("key1", "value1");
        assert!(res.is_some());
        // println!("set -> {:?}", res);
        let res = config.get("key1");
        assert!(res.is_some());
        // println!("get -> {:?}", res);
        assert_eq!(res, Some("value1"));
        let res = config.add_section("", "mod1");
        assert!(res.is_some());
        // println!("add_section -> {:?}", res);
        let res = config.set("mod1.key1", "value2");
        assert!(res.is_some());
        // println!("set -> {:?}", res);
        let res = config.get("mod1.key1");
        // println!("get -> {:?}", res);
        assert_eq!(res, Some("value2"));
    }
}
