extern crate rand;

use std::io::{Error, ErrorKind};
use std::net::UdpSocket;

use crate::dns_packet::*;
use crate::dns_resolver::DnsResolver;
use crate::settings::DnsSettings;
use crate::{log_debug, log_error, log_info};

pub struct DnsServer {
  listening_port: u16,
  resolver: DnsResolver,
}

impl DnsServer {
  pub fn new(settings: DnsSettings, resolver: DnsResolver) -> DnsServer {
    Self {
      listening_port: settings.listening_port,
      resolver,
    }
  }

  pub fn run(&mut self) -> Result<(), Error> {
    let socket = UdpSocket::bind(("0.0.0.0", self.listening_port))?;
    socket.set_nonblocking(true)?;

    loop {
      match self.handle_query(&socket) {
        Ok(_) => {
          log_debug!("Done with query :)")
        }
        Err(e) if e.kind() == ErrorKind::WouldBlock => {}
        Err(e) => log_error!("An error occurred: {}", e),
      }
    }
  }

  fn handle_query(&self, socket: &UdpSocket) -> Result<(), Error> {
    let mut res: [u8; 512] = [0; 512];
    let (_, src) = socket.recv_from(&mut res)?;
    log_debug!("done receive");
    let request = DnsPacket::from_bytes(&res)?;

    let packet = self.resolver.answer_question(request);

    let response_data = packet.to_bytes();
    log_info!(
      "Reparsed:\n {:#?}",
      DnsPacket::from_bytes(response_data.as_slice())
    );
    socket.send_to(&response_data, src)?;
    Ok(())
  }
}
