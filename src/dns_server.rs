extern crate rand;

use std::io::Error;
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{Builder, sleep};
use std::time::Duration;

use crate::dns_packet::*;
use crate::dns_resolver::DnsResolver;
use crate::settings::DnsSettings;
use crate::{ignore_result_and_log_error, log_error, log_warn};

pub trait DnsServer {
  fn run(self) -> Result<(), Error>;
}

pub struct DnsUdpServer {
  settings: Arc<DnsSettings>,
  request_queue: Arc<Mutex<Vec<(SocketAddr, DnsPacket)>>>,
  request_cond: Arc<Condvar>
}

impl DnsUdpServer {
  pub fn new(settings: DnsSettings) -> DnsUdpServer {
    Self {
      settings: Arc::new(settings),
      request_queue: Arc::new(Mutex::new(Vec::new())),
      request_cond: Arc::new(Condvar::new()),
    }
  }
}

impl DnsServer for DnsUdpServer {
  fn run(self) -> Result<(), Error> {
    let socket = UdpSocket::bind(("0.0.0.0", self.settings.listening_port))?;


    for thread_num in 0..self.settings.thread_count {
      let request_queue = self.request_queue.clone();
      let request_cond = self.request_cond.clone();
      let settings = self.settings.clone();
      let socket_clone = match socket.try_clone() {
        Ok(x) => x,
        Err(error) => {
          log_error!("Failed to clone socket: {}", error);
          continue;
        }
      };

      let _ = Builder::new()
        .name(format!("DnsUdpServer-process-requests-{}", thread_num))
        .spawn(move || {
          loop {
            // get thing from queue
            let (source, request_packet) = match request_queue
              .lock()
              .ok()
              .and_then(|x| request_cond.wait(x).ok())
              .and_then(|mut x| x.pop()) {
              Some(x) => x,
              None => {
                log_warn!("Request queue was empty when we were notified that something was in there :(");
                continue;
              }
            };

            sleep(Duration::from_millis(1000));

            // process request
            let resolver = DnsResolver::new(settings.database_file.clone(), settings.remote_lookup_port);
            let response_packet = resolver.answer_question(request_packet);

            // send result back
            ignore_result_and_log_error!(socket_clone.send_to(response_packet.to_bytes().as_slice(), source));
          }
        })?;
    }

    let _ = Builder::new()
      .name("DnsUdpServer-incoming-requests".to_string())
      .spawn(move || {
        loop {
          let mut res: [u8; 512] = [0; 512];
          let (_, src) = match socket.recv_from(&mut res) {
            Ok(x) => x,
            Err(error) => {
              log_error!("There was a problem with reading from the UDP socket :( {}", error);
              continue;
            }
          };

          let request = match DnsPacket::from_bytes(&res) {
            Ok(packet) => packet,
            Err(error) => {
              log_error!("There was a problem with parsing the packet :( {}", error);
              continue;
            }
          };

          match self.request_queue.lock() {
            Ok(mut queue) => {
              queue.push((src, request));
              self.request_cond.notify_one();
            }
            Err(error) => {
              log_error!("Failed to add packet to request queue: {}", error);
            }
          }
        }
      })?;

    Ok(())
  }
}

pub struct DnsTcpServer {
  listening_port: u16,
  thread_count: u32,
  use_tcp: bool,
  resolver: DnsResolver,
}
