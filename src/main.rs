pub mod dns_packet;
pub mod dns_server;

extern crate clap;
extern crate yaml_rust;
extern crate notify;

use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::io::ErrorKind;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::mpsc::channel;
use std::thread;
use std::time::Duration;

use clap::Parser;
use yaml_rust::YamlLoader;
use notify::{Watcher, RecursiveMode, watcher};

use crate::dns_server::DnsServer;
use crate::dns_packet::*;

#[derive(Parser, Debug)]
#[clap(author, version, about = "A simple dns server :)", long_about = None)]
struct Args {
  #[clap(short, long, value_parser, default_value = "~/.config/simpledns/dns.config.yaml")]
  config: String,
}

fn insert(map: &mut HashMap<String, Vec<DnsRecord>>, key: String, value: DnsRecord) {
  match map.get(&key) {
    Some(mut current) => {
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

fn load_settings(filename: String) -> Result<(u16, u16, Vec<String>, HashMap<String, Vec<DnsRecord>>), Box<dyn Error>> {
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
      let mut parsed_records = HashMap::new();
      let config_records = match config_settings["records"].as_vec() {
        Some(records) => {
          let mut res = Vec::new();
          for rec in records {
            let mut name;
            match rec["domain"].as_str() {
              Some(x) => name = x,
              None => continue
            }
            let query_type = match rec["type"].as_str() {
              Some(x) => DnsQueryType::from_string(x),
              None => DnsQueryType::Unknown(0),
            };
            let class = match rec["class"].as_i64() {
              Some(x) => x as u16,
              None => 1
            };
            let ttl = match rec["ttl"].as_i64() {
              Some(x) => x as u32,
              None => 600
            };
            let mut record_preamble = DnsRecordPreamble::new();
            record_preamble.domain = name.to_string();
            record_preamble.query_type = query_type;
            record_preamble.class = class;
            record_preamble.ttl = ttl;
            match query_type {
              DnsQueryType::Unknown(_) => { eprintln!("Unknown record type for record '{}'", record_preamble.domain); },
              DnsQueryType::DROP => {
                res.push(DnsRecord::DROP(DnsRecordDROP::new(record_preamble)));
              }
              DnsQueryType::AAAA => {
                match rec["ip"].as_str() {
                  Some(x) => res.push(DnsRecord::AAAA(DnsRecordAAAA::new(&mut record_preamble, Ipv4Addr::from_str(x)?))),
                  None => { eprintln!("No ip given for record '{}'. Skipping...", record_preamble.domain ); continue; }
                }
              },
              DnsQueryType::A => {
                match rec["ip"].as_str() {
                  Some(x) => res.push(DnsRecord::A(DnsRecordA::new(&mut record_preamble, Ipv4Addr::from_str(x)?))),
                  None => { eprintln!("No ip given for record '{}'. Skipping...", record_preamble.domain ); continue; }
                }
              },
              DnsQueryType::NS => {
                match rec["hostname"].as_str() {
                  Some(x) => res.push(DnsRecord::NS(DnsRecordNS::new(&mut record_preamble, x.to_string()))),
                  None => { eprintln!("No hostname given for record '{}'. Skipping...", record_preamble.domain ); continue; }
                }
              },
              DnsQueryType::CNAME => {
                match rec["hostname"].as_str() {
                  Some(x) => res.push(DnsRecord::CNAME(DnsRecordCNAME::new(&mut record_preamble, x.to_string()))),
                  None => { eprintln!("No hostname given for record '{}'. Skipping...", record_preamble.domain ); continue; }
                }
              },
              DnsQueryType::MX => {
                let priority = match rec["priority"].as_i64() {
                  Some(x) => x as u16,
                  None => 1,
                };
                match rec["hostname"].as_str() {
                  Some(x) => res.push(DnsRecord::A(DnsRecordA::new(&mut record_preamble, Ipv4Addr::from_str(x)?))),
                  None => { eprintln!("No hostname given for record '{}'. Skipping...", record_preamble.domain ); continue; }
                }
              },
            }
          }
          res
        }
        None => { println!("No records found in config!"); Vec::new() }
      };
      for rec in config_records {
        match &rec {
          DnsRecord::A(r) => insert(&mut parsed_records, r.preamble.domain.clone(), rec),
          DnsRecord::Unknown(r) => insert(&mut parsed_records, r.preamble.domain.clone(), rec),
          DnsRecord::NS(r) => insert(&mut parsed_records, r.preamble.domain.clone(), rec),
          DnsRecord::CNAME(r) => insert(&mut parsed_records, r.preamble.domain.clone(), rec),
          DnsRecord::MX(r) => insert(&mut parsed_records, r.preamble.domain.clone(), rec),
          DnsRecord::AAAA(r) => insert(&mut parsed_records, r.preamble.domain.clone(), rec),
          DnsRecord::DROP(r) => insert(&mut parsed_records, r.preamble.domain.clone(), rec),
        }
      }
      Ok((listen_port, backup_port, servers, parsed_records))
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
  println!("Records: {:#?}", records);

  let mut server = DnsServer::new(listen_port, backup_port, servers, records);
  
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
