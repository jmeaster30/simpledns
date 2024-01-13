extern crate rand;

use std::io::{Error, ErrorKind};
use std::net::UdpSocket;
use std::sync::mpsc::{Receiver, TryRecvError};

use crate::dns_packet::*;
use crate::{log_debug, log_error, log_info, log_warn};
use crate::dns_resolver::DnsResolver;
use crate::settings::DnsSettings;

pub struct DnsServer {
  settings: DnsSettings,
  resolver: DnsResolver,
}

impl DnsServer {
  pub fn new(settings: DnsSettings, resolver: DnsResolver) -> DnsServer {
    Self {
      settings,
      resolver
    }
  }

  pub fn run(&mut self, update_receiver: Receiver<DnsSettings>) -> Result<(), Error> {
    let socket = UdpSocket::bind(("0.0.0.0", self.settings.listening_port))?;
    socket.set_nonblocking(true)?;

    let mut update_receiver_disconnected = false;

    loop {
      if !update_receiver_disconnected {
        match update_receiver.try_recv() {
          Ok(message) => {
            log_debug!("message: {:#?}", message);
            self.settings = message;
            log_debug!("Servers: {:#?}", self.settings.servers);
          },
          Err(TryRecvError::Empty) => {
            // empty queue do nothing
            //println!("empty file update queue")
          },
          Err(TryRecvError::Disconnected) => {
            update_receiver_disconnected = true;
            log_warn!("WARNING!!!!! Update Receiver Has Disconnected: The dns server will continue to run but changes to the configuration file will not automatically update the server :(");
          }
        }
      }
      match self.handle_query(&socket) {
        Ok(_) => {log_debug!("Done with query :)")},
        Err(e) if e.kind() == ErrorKind::WouldBlock => {},
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
    log_info!("Reparsed:\n {:#?}", DnsPacket::from_bytes(response_data.as_slice()));
    socket.send_to(&response_data, src)?;
    Ok(())
  }

}
