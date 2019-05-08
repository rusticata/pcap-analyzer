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
    /// Get an entry by path. If the input argument contains dots, the path is split
    /// into keys, each key being requested recursively.
    pub fn get<T: AsRef<str>>(&self, k: T) -> Option<&str> {
        let mut item = &self.value;
        for key in k.as_ref().split(".") {
            item = item.get(key)?;
        }
        item.as_str()
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
