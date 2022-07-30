pub mod dns_packet;
pub mod dns_server;

extern crate clap;
extern crate yaml_rust;

use std::collections::HashMap;
use std::error::Error;
use std::fs;

use clap::Parser;
use yaml_rust::YamlLoader;

use crate::dns_server::DnsServer;

#[derive(Parser, Debug)]
#[clap(author, version, about = "A simple dns server :)", long_about = None)]
struct Args {
  #[clap(short, long, value_parser, default_value = "~/.config/simpledns/dns.config.yaml")]
  config: String,
}

fn main() -> Result<(), Box<dyn Error>> {
  let args = Args::parse();
  println!("Loading from config file '{}'...", args.config);
  
  let contents = fs::read_to_string(args.config)
    .expect("Aw man, there was an issue while opening the config file :(");

  let config_settings = &YamlLoader::load_from_str(contents.as_str())?[0];

  let listen_port = match config_settings["listen-port"].as_i64() {
    Some(x) => x as u16,
    None => 53
  };
  let backup_port = match config_settings["backup-port"].as_i64() {
    Some(x) => x as u16,
    None => 42069
  };
  let servers = match config_settings["servers"].as_vec() {
    Some(server) => server.into_iter().map(|entry| match entry.as_str() {
      Some(x) => x.to_string(),
      None => "".to_string()
    }).collect(),
    None => Vec::new()
  };

  println!("Listening Port: {}", listen_port);
  println!("Backup Port: {}", backup_port);
  println!("Servers: {:#?}", servers);

  let server = DnsServer::new(listen_port, backup_port, servers, HashMap::new());
  server.run()?;
  Ok(())
}
