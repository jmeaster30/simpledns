use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::io::ErrorKind;
use std::net::Ipv4Addr;
use std::path::Path;
use std::str::FromStr;
use std::sync::mpsc::Sender;
use notify::{Event, EventHandler, recommended_watcher, RecursiveMode, Watcher};
use yaml_rust::YamlLoader;
use crate::dns_packet::{DnsQueryType, DnsRecord, DnsRecordA, DnsRecordAAAA, DnsRecordCNAME, DnsRecordDROP, DnsRecordMX, DnsRecordNS, DnsRecordPreamble};
use crate::{insert, log_error, log_info};

#[derive(Clone, Debug)]
pub struct DnsSettings {
    pub listening_port: u16,
    pub backup_port: u16,
    pub servers: Vec<String>,
    pub records: HashMap<String, Vec<DnsRecord>>,
}

impl DnsSettings {
    pub fn load(filename: String) -> Result<Self, Box<dyn Error>> {
        let contents = fs::read_to_string(filename)
            .expect("Aw man, there was an issue while opening the config file :(");

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
                            let name;
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
                                        Some(x) => res.push(DnsRecord::MX(DnsRecordMX::new(&mut record_preamble, priority, x.to_string()))),
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
                Ok(DnsSettings {
                    listening_port: listen_port,
                    backup_port,
                    servers,
                    records: parsed_records,
                })
            }
            None => Err(Box::new(std::io::Error::new(ErrorKind::Other, "Parsing the config file lead to no yaml documents :(")))
        }
    }
}

struct ConfigFileWatcher {
    config_file_path: String,
    server_update_sender: Sender<DnsSettings>,
}

impl ConfigFileWatcher {
    pub fn new(config_file_path: String, server_update_sender: Sender<DnsSettings>) -> Self {
        Self { config_file_path, server_update_sender }
    }
}

impl EventHandler for ConfigFileWatcher {
    fn handle_event(&mut self, event: notify::Result<Event>) {
        match event {
            Ok(_) => {
                log_info!("Config file updated '{}'", self.config_file_path.as_str());
                match DnsSettings::load(self.config_file_path.clone()) {
                    Ok(settings) => {
                        let _ = self.server_update_sender.send(settings);
                    }
                    Err(error) => log_error!("FAILED TO LOAD SETTING: {:?}", error)
                }
            }
            Err(e) => log_error!("FILE WATCH ERROR: {:?}", e)
        }
    }
}

pub fn build_config_file_watcher(config_file_path: String, channel_sender: Sender<DnsSettings>) -> notify::Result<()> {
    let handler = ConfigFileWatcher::new(config_file_path.clone(), channel_sender);
    let mut watcher = recommended_watcher(handler).unwrap();
    watcher.watch(Path::new(&config_file_path), RecursiveMode::NonRecursive)
}
