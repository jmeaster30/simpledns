pub mod dns_packet;
pub mod dns_server;
mod settings;
mod logger;
mod dns_resolver;

extern crate clap;
extern crate yaml_rust;
extern crate notify;

use std::collections::HashMap;
use std::error::Error;
use std::sync::mpsc::channel;

use clap::Parser;

use crate::dns_server::DnsServer;
use crate::dns_packet::*;
use crate::dns_resolver::DnsResolver;
use crate::settings::{build_config_file_watcher, DnsSettings};

#[derive(Parser, Debug)]
#[clap(author, version, about = "A simple dns server :)", long_about = None)]
struct Args {
  #[clap(short, long, value_parser, default_value = "~/.config/simpledns/dns.config.yaml")]
  config: String,
}

fn insert(map: &mut HashMap<String, Vec<DnsRecord>>, key: String, value: DnsRecord) {
  match map.get(&key) {
    Some(current) => {
      let mut updated = Vec::new();
      for c in current {
        updated.push(c.clone());
      }
      updated.push(value);
      map.insert(key, updated.to_vec())
    }
    None => map.insert(key, vec![value])
  };
}



fn main() -> Result<(), Box<dyn Error>> {
  let args = Args::parse();
  log_info!("Loading from config file '{}'...", args.config);
  
  let settings = DnsSettings::load(args.config.clone())?;

  log_info!("Listening Port: {}", settings.listening_port);
  log_info!("Backup Port: {}", settings.backup_port);
  log_info!("Servers: {:#?}", settings.servers);
  log_info!("Records: {:#?}", settings.records);

  let mut server = DnsServer::new(settings.clone(), DnsResolver::new(settings));

  let (server_update_sender, server_update_receiver) = channel();

  build_config_file_watcher(args.config.clone(), server_update_sender)?;

  let _handle = std::thread::spawn(move || {
    let _ = server.run(server_update_receiver);
  });

  loop {}

  // TODO How to deal with this being dead code
  _handle.join().unwrap();
  Ok(())
}
