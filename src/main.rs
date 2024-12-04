mod cli;
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
use std::path::Path;

use clap::{Args, Parser, Subcommand};
use cli::{add_record, add_record_interactive, list_records};

use crate::dns_server::{DnsServer, DnsTcpServer, DnsUdpServer};
use crate::settings::DnsSettings;
use crate::simple_database::SimpleDatabase;

#[cfg(feature = "tui")]
use crate::tui::base::tui_start;

#[derive(Parser, Debug)]
#[command(author, version, about = "A simple dns server :)", long_about = None)]
struct Cli {
  #[command(subcommand)]
  command: Commands,
}

#[derive(Args, Clone, Debug)]
struct RecordFilters {
  #[arg(long, value_parser)]
  domain: Option<String>,
  #[arg(long, value_parser(["A", "NS", "CNAME", "MX", "AAAA", "DROP"]))]
  query_type: Option<String>,
  #[arg(long, value_parser)]
  class: Option<u16>,
  #[arg(long, value_parser)]
  ttl: Option<u32>,
  #[arg(long, value_parser)]
  host: Option<String>,
  #[arg(long, value_parser)]
  ip: Option<String>,
  #[arg(long, value_parser)]
  priority: Option<u16>,
}

#[derive(Args, Clone, Debug)]
struct RecordArgs {
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
    #[command(flatten)]
    args: RecordArgs,
  },
  List {
    #[arg(short, long, value_parser)]
    config: Option<String>,
    #[command(flatten)]
    filters: RecordFilters,
  }
}

fn main() -> Result<(), Box<dyn Error>> {
  let args = Cli::parse();
  log_debug!("Command: {:?}", args.command);

  match args.command {
    Commands::Init { config } => {
      let settings = match config {
        Some(filename) => DnsSettings::load_from_file(filename.clone()),
        None                   => DnsSettings::load_default(),
      };
      let settings = settings.expect("Error reading settings!");

      log_debug!("Database File Path: {:#?}", settings.database_file);

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
      log_debug!("Settings: {:?}", settings);
      let server_udp = DnsUdpServer::new(settings.clone());
      let server_tcp = DnsTcpServer::new(settings.clone());

      let _handle = std::thread::spawn(move || {
        if settings.use_udp {
          let _ = server_udp.run();
          log_info!("Successfully started UDP server :)");
        } else {
          log_debug!("UDP server was not started due to configuration settings.");
        }

        if settings.use_tcp {
          let _ = server_tcp.run();
          log_info!("Successfully started TCP server :)");
        } else {
          log_debug!("TCP server was not started due to configuration settings.");
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
    Commands::Tui { .. } => {
      log_error!("simpledns was not built with the TUI feature :( please rebuild with `cargo build --features \"tui\"`...")
    }
    Commands::Add { config, interactive, .. } if interactive => {
      let settings = match config {
        Some(filename) => DnsSettings::load_from_file(filename.clone()),
        None                   => DnsSettings::load_default(),
      };
      let settings = settings.expect("Error reading settings!");
      log_debug!("Database File Path: {:#?}", settings.database_file);

      add_record_interactive(settings)?;
    }
    Commands::Add { config, interactive, args } if !interactive => {
      let settings = match config {
        Some(filename) => DnsSettings::load_from_file(filename.clone()),
        None                   => DnsSettings::load_default(),
      };
      let settings = settings.expect("Error reading settings!");
      log_debug!("Database File Path: {:#?}", settings.database_file);

      add_record(args, settings)?;
    }
    Commands::List { config, filters} => {
      let settings = match config {
        Some(filename) => DnsSettings::load_from_file(filename.clone()),
        None                   => DnsSettings::load_default(),
      }.expect("Error reading settings :(");

      list_records(settings, filters)?;
    }
    _ => log_error!("Unknown command :( \n{:#?}", args),
  }

  Ok(())
}

