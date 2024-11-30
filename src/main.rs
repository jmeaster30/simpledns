pub mod dns_packet;
mod dns_resolver;
pub mod dns_server;
mod macros;
mod settings;
mod simple_database;

#[cfg(feature = "tui")]
mod tui;

extern crate clap;
extern crate yaml_rust;

use std::error::Error;
use std::fs::{create_dir_all, File};
use std::io::{stdin, stdout, Write};
use std::net::Ipv4Addr;
use std::path::Path;
use std::str::FromStr;

use clap::{Parser, Subcommand};
use crate::dns_packet::{DnsQueryType, DnsRecord, DnsRecordA, DnsRecordAAAA, DnsRecordCNAME, DnsRecordDROP, DnsRecordMX, DnsRecordNS, DnsRecordPreamble};

use crate::dns_server::{DnsServer, DnsTcpServer, DnsUdpServer};
use crate::settings::DnsSettings;
use crate::simple_database::SimpleDatabase;

#[cfg(feature = "tui")]
use crate::tui::base::tui_start;

#[derive(Parser, Debug)]
#[command(author, version, about = "A simple dns server :)", long_about = None)]
struct Args {
  #[command(subcommand)]
  command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
  Start {
    #[arg(short, long, value_parser)]
    config: Option<String>,
  },
  Init {
    #[arg(short, long, value_parser)]
    config: Option<String>,
  },
  Tui {
    #[arg(short, long, value_parser)]
    config: Option<String>,
  },
  Add {
    #[arg(short, long, value_parser)]
    config: Option<String>,
    #[arg(short, long, action)]
    interactive: bool,
    #[arg(long, value_parser, required_unless_present("interactive"))]
    domain: Option<String>,
    #[arg(long, value_parser(["A", "NS", "CNAME", "MX", "AAAA", "DROP"]), required_unless_present("interactive"))]
    query_type: Option<String>,
    #[arg(long, value_parser, default_value = "1")]
    class: u16,
    #[arg(long, value_parser, default_value = "300")]
    ttl: u32,
    #[arg(long, value_parser, required_if_eq_any([
      ("query_type", "NS"),
      ("query_type", "CNAME"),
      ("query_type", "MX")
    ]))]
    host: Option<String>,
    #[arg(long, value_parser, required_if_eq_any([
      ("query_type", "A"),
      ("query_type", "AAAA"),
    ]))]
    ip: Option<String>,
    #[arg(long, value_parser, required_if_eq("query_type", "MX"))]
    priority: Option<u16>,
  },
}

fn main() -> Result<(), Box<dyn Error>> {
  let args = Args::parse();
  log_info!("Command: {:?}", args.command);

  match args.command {
    Commands::Init { config } => {
      let settings = match config {
        Some(filename) => DnsSettings::load_from_file(filename.clone()),
        None                   => DnsSettings::load_default(),
      };
      let settings = settings.expect("Error reading settings!");

      log_info!("Database File Path: {:#?}", settings.database_file);

      let path = Path::new(settings.database_file.as_str());
      let parent = path.parent().unwrap();
      log_debug!("parent: {:?}", parent);
      create_dir_all(parent)?;
      File::create(path)?;

      let database = SimpleDatabase::new(settings.database_file);
      match database.initialize() {
        Ok(_) => log_info!("Successfully initialized the database :)"),
        Err(error) => log_error!("There was an error while initializing the database :( | {}", error),
      }
    }
    Commands::Start { config } => {
      let settings = match config {
        Some(filename) => DnsSettings::load_from_file(filename.clone()),
        None                   => DnsSettings::load_default(),
      };
      let settings = settings.expect("Error reading settings!");
      log_info!("Settings: {:?}", settings);

      let server_udp = DnsUdpServer::new(settings.clone());
      let server_tcp = DnsTcpServer::new(settings.clone());

      let _handle = std::thread::spawn(move || {
        if settings.use_udp {
          let _ = server_udp.run();
          log_info!("Successfully started UDP server :)");
        } else {
          log_info!("UDP server was not started due to configuration settings.");
        }

        if settings.use_tcp {
          let _ = server_tcp.run();
          log_info!("Successfully started TCP server :)");
        } else {
          log_info!("TCP server was not started due to configuration settings.");
        }
      });

      loop {}

      // TODO How to deal with this being dead code
      // #[allow(unreachable_code)] doesn't work
      _handle.join().unwrap();
    }
    #[cfg(feature = "tui")]
    Commands::Tui { config } => {
      let settings = match config {
        Some(filename) => DnsSettings::load_from_file(filename.clone()),
        None                   => DnsSettings::load_default(),
      }?;
      tui_start(&settings)?;
    }
    #[cfg(not(feature = "tui"))]
    Commands::Tui { config } => {
      log_error!("simpledns was not built with the TUI feature :( please rebuild with `cargo build --features \"tui\"`...")
    }
    Commands::Add { config, interactive, .. } if interactive => {
      let settings = match config {
        Some(filename) => DnsSettings::load_from_file(filename.clone()),
        None                   => DnsSettings::load_default(),
      };
      let settings = settings.expect("Error reading settings!");
      log_info!("Database File Path: {:#?}", settings.database_file);

      let domain = get_input("Domain: ", None, "A domain is required.", |x| !x.is_empty()); // TODO should check for valid domain
      let query_type = DnsQueryType::from_string(get_input("Record Type: ",
                                None,
                                "A record type is required [A, NS, CNAME, MX, AAAA, DROP]",
                                |x| ["A", "NS", "CNAME", "MX", "AAAA", "DROP"].contains(&x.to_uppercase().as_str())).as_str());
      let class = get_input("Class [default 1]: ",
                            Some("1".to_string()),
                            "A valid u16 must be supplied.",
                            |x| !x.is_empty() && x.parse::<u16>().is_ok()).parse::<u16>().unwrap();
      let ttl = get_input("TTL [default 300]: ",
                          Some("300".to_string()),
                          "A valid u32 must be supplied.",
                          |x| !x.is_empty() && x.parse::<u32>().is_ok()).parse::<u32>().unwrap();
      let preamble = DnsRecordPreamble::build(domain, query_type, class, ttl);

      let record = match query_type {
        DnsQueryType::Unknown(_) => panic!("Impossible state"),
        DnsQueryType::A => {
          let ip = get_input("IP: ", None, "A valid ip address is required.", |x| Ipv4Addr::from_str(x.as_str()).is_ok());
          DnsRecord::A(DnsRecordA::new(preamble, Ipv4Addr::from_str(ip.as_str()).unwrap()))
        }
        DnsQueryType::NS => {
          let host = get_input("Host: ", None, "A host is required.", |x| !x.is_empty());
          DnsRecord::NS(DnsRecordNS::new(preamble, host))
        }
        DnsQueryType::CNAME => {
          let host = get_input("Host: ", None, "A host is required.", |x| !x.is_empty());
          DnsRecord::CNAME(DnsRecordCNAME::new(preamble, host))
        }
        DnsQueryType::MX => {
          let host = get_input("Host: ", None, "A host is required.", |x| !x.is_empty());
          let priority = get_input("Priority: ", None, "A valid u16 priority is required.", |x| !x.is_empty() && x.parse::<u16>().is_ok()).parse::<u16>().unwrap();
          DnsRecord::MX(DnsRecordMX::new(preamble, priority, host))
        }
        DnsQueryType::AAAA => {
          let ip = get_input("IP: ", None, "A valid ip address is required.", |x| Ipv4Addr::from_str(x.as_str()).is_ok());
          DnsRecord::AAAA(DnsRecordAAAA::new(preamble, Ipv4Addr::from_str(ip.as_str()).unwrap()))
        }
        DnsQueryType::DROP => DnsRecord::DROP(DnsRecordDROP::new(preamble))
      };

      let database = SimpleDatabase::new(settings.database_file);
      database.insert_record(record.clone(), false)?;
      log_info!("Successfully added record: {:?}", record);
    }
    Commands::Add { config, interactive, domain, query_type, class, ttl, host, ip, priority } if !interactive => {
      let settings = match config {
        Some(filename) => DnsSettings::load_from_file(filename.clone()),
        None                   => DnsSettings::load_default(),
      };
      let settings = settings.expect("Error reading settings!");
      log_info!("Database File Path: {:#?}", settings.database_file);

      let domain = domain.unwrap();
      let query_type = DnsQueryType::from_string(query_type.unwrap().as_str());
      let preamble = DnsRecordPreamble::build(domain, query_type, class, ttl);
      let record = match query_type {
        DnsQueryType::Unknown(_) => panic!("Impossible state"),
        DnsQueryType::A => DnsRecord::A(DnsRecordA::new(preamble, Ipv4Addr::from_str(ip.unwrap().as_str()).expect("Couldn't parse ipv4 address"))),
        DnsQueryType::NS => DnsRecord::NS(DnsRecordNS::new(preamble, host.unwrap())),
        DnsQueryType::CNAME => DnsRecord::CNAME(DnsRecordCNAME::new(preamble, host.unwrap())),
        DnsQueryType::MX => DnsRecord::MX(DnsRecordMX::new(preamble, priority.unwrap(), host.unwrap())),
        DnsQueryType::AAAA => DnsRecord::AAAA(DnsRecordAAAA::new(preamble, Ipv4Addr::from_str(ip.unwrap().as_str()).expect("Couldn't parse ipv4 address"))),
        DnsQueryType::DROP => DnsRecord::DROP(DnsRecordDROP::new(preamble)),
      };

      let database = SimpleDatabase::new(settings.database_file);
      database.insert_record(record.clone(), false)?;
      log_info!("Successfully added record: {:?}", record);
    }
    _ => log_error!("Unknown command :( \n{:#?}", args),
  }

  Ok(())
}

pub fn get_input(message: &str, default_value: Option<String>, error_message: &str, validate: fn(String) -> bool) -> String {
  loop {
    let mut s = String::new();
    print!("{}", message);
    let _ = stdout().flush();
    let _ = stdin().read_line(&mut s).expect("Did not enter a correct string");
    s = s.trim_matches(&['\r', '\n', ' ', '\t']).to_string();
    if validate(s.clone()) {
      return s;
    } else if let Some(value) = default_value.clone() {
      return value;
    }
    println!("{}", error_message);
  }
}
