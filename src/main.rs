pub mod dns_packet;
mod dns_resolver;
pub mod dns_server;
mod logger;
mod settings;
mod simple_database;

extern crate clap;
extern crate yaml_rust;

use std::error::Error;
use std::fs::{create_dir_all, File};
use std::path::Path;

use clap::{Parser, Subcommand};

use crate::dns_resolver::DnsResolver;
use crate::dns_server::DnsServer;
use crate::settings::DnsSettings;
use crate::simple_database::SimpleDatabase;

#[derive(Parser, Debug)]
#[command(author, version, about = "A simple dns server :)", long_about = None)]
struct Args {
  #[command(subcommand)]
  command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
  Start {
    #[arg(short, long, value_parser, default_value = "~/.config/simpledns/dns.config.yaml")]
    config: String,
  },
  Initialize {
    #[arg(short, long, value_parser, default_value = "~/.config/simpledns/dns.config.yaml")]
    config: String,
  },
}

fn main() -> Result<(), Box<dyn Error>> {
  let args = Args::parse();
  log_info!("Command: {:?}", args.command);

  match args.command {
    Some(Commands::Initialize { config }) => {
      log_info!("Loading from config file '{}'...", config);
      let settings = DnsSettings::load(config.clone())?;
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
    Some(Commands::Start { config }) => {
      log_info!("Loading from config file '{}'...", config);
      let settings = DnsSettings::load(config.clone())?;
      log_info!("Listening Port: {}", settings.listening_port);
      log_info!("Backup Port: {}", settings.remote_lookup_port);
      log_info!("Database File Path: {:#?}", settings.database_file);

      let mut server = DnsServer::new(settings.clone(), DnsResolver::new(settings));

      let _handle = std::thread::spawn(move || {
        let _ = server.run();
      });

      loop {}

      // TODO How to deal with this being dead code
      _handle.join().unwrap();
    }
    _ => log_error!("Unknown command :("),
  }

  Ok(())
}
