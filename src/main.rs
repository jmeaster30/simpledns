pub mod dns_packet;
pub mod dns_server;

extern crate clap;
extern crate yaml_rust;
extern crate notify;

use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::io::ErrorKind;
use std::sync::mpsc::channel;
use std::thread;
use std::time::Duration;

use clap::Parser;
use yaml_rust::YamlLoader;
use notify::{Watcher, RecursiveMode, watcher};

use crate::dns_server::DnsServer;
use crate::dns_packet::DnsRecord;

#[derive(Parser, Debug)]
#[clap(author, version, about = "A simple dns server :)", long_about = None)]
struct Args {
  #[clap(short, long, value_parser, default_value = "~/.config/simpledns/dns.config.yaml")]
  config: String,
}

fn load_settings(filename: String) -> Result<(u16, u16, Vec<String>, HashMap<String, DnsRecord>), Box<dyn Error>> {
  let contents = fs::read_to_string(filename)
    .expect("Aw man, there was an issue while opening the config file :(");

  println!("{}", contents.len());

  let yaml_files = &YamlLoader::load_from_str(contents.as_str())?;
  let config_settings_option = &yaml_files.get(0);
  match config_settings_option {
    Some(config_settings) => {
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
      Ok((listen_port, backup_port, servers, HashMap::new()))
    }
    None => Err(Box::new(std::io::Error::new(ErrorKind::Other, "Parsing the config file lead to no yaml documents :(")))
  }
  
}

fn main() -> Result<(), Box<dyn Error>> {
  let args = Args::parse();
  println!("Loading from config file '{}'...", args.config);
  
  let (listen_port, backup_port, servers, records) = load_settings(args.config.clone())?;

  println!("Listening Port: {}", listen_port);
  println!("Backup Port: {}", backup_port);
  println!("Servers: {:#?}", servers);

  let mut server = DnsServer::new(listen_port, backup_port, servers, HashMap::new());
  
  let (fw_sender, fw_receiver) = channel();
  let mut watcher = watcher(fw_sender, Duration::from_secs(10)).unwrap();
  watcher.watch(args.config.clone(), RecursiveMode::NonRecursive)?;

  let (server_update_sender, server_update_receiver) = channel();

  let handle = std::thread::spawn(move || {
    server.run(server_update_receiver);
  });

  loop {
    match fw_receiver.recv() {
      Ok(event) => {
        println!("{}", args.config.as_str());
        match load_settings(args.config.clone()) {
          Ok((_, _, servers, records)) => {
            server_update_sender.send((servers, records));
          }
          Err(error) => eprintln!("FAILED TO LOAD SETTING: {:?}", error)
        }
      }
      Err(e) => eprintln!("FILE WATCH ERROR: {:?}", e)
    }
  }

  handle.join().unwrap();
  Ok(())
}
