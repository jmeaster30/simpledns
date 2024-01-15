use std::error::Error;
use std::fs;
use std::io::ErrorKind;
use yaml_rust::YamlLoader;

extern crate shellexpand;

#[derive(Clone, Debug)]
pub struct DnsSettings {
  pub listening_port: u16,
  pub remote_lookup_port: u16,
  pub database_file: String,
  pub thread_count: u32,
  pub use_udp: bool,
  pub use_tcp: bool,
}

impl DnsSettings {
  pub fn load(filename: String) -> Result<Self, Box<dyn Error>> {
    let contents = fs::read_to_string(shellexpand::full(filename.as_str()).unwrap().to_string())
      .expect("Aw man, there was an issue while opening the config file :(");

    let yaml_files = &YamlLoader::load_from_str(contents.as_str())?;
    let config_settings_option = &yaml_files.get(0);
    match config_settings_option {
      Some(config_settings) => {
        let listening_port = match config_settings["listening-port"].as_i64() {
          Some(x) => x as u16,
          None => 53,
        };
        let remote_lookup_port = match config_settings["remote-lookup-port"].as_i64() {
          Some(x) => x as u16,
          None => 42069,
        };
        let thread_count = match config_settings["thread-count"].as_i64() {
          Some(x) => x as u32,
          None => 1, // TODO is this the best default?
        };
        let use_udp = match config_settings["use-udp"].as_bool() {
          Some(x) => x,
          None => true,
        };
        let use_tcp = match config_settings["use-tcp"].as_bool() {
          Some(x) => x,
          None => true,
        };

        let database_file = shellexpand::full(
            config_settings["database-file"]
              .as_str()
              .unwrap_or_else(|| "~/.config/simpledns/simpledns.sqlite.db")
          )
          .unwrap()
          .to_string();

        Ok(DnsSettings {
          listening_port,
          remote_lookup_port,
          database_file,
          thread_count,
          use_udp,
          use_tcp,
        })
      }
      None => Err(Box::new(std::io::Error::new(
        ErrorKind::Other,
        "Parsing the config file lead to no yaml documents :(",
      ))),
    }
  }
}
