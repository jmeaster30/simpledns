extern crate rand;

use std::io::{Error, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, Condvar, Mutex};
use std::sync::mpsc::{channel, Sender};
use std::thread::Builder;
use rand::random;

use crate::dns_packet::*;
use crate::dns_resolver::DnsResolver;
use crate::settings::DnsSettings;
use crate::{ignore_result_and_log_error, ignore_result_or_log_error_continue, log_error, log_warn, return_result_or_log_error_continue};

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

            // process request
            let resolver = DnsResolver::new(settings.database_file.clone(), settings.remote_lookup_port);
  
            match resolver.answer_question(request_packet) {
              Ok(result) => {
                ignore_result_and_log_error!(socket_clone.send_to(result.to_bytes().as_slice(), source));
              }
              Err(error) => {
                log_error!("Resolver error {}", error)
              }
            }
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
  settings: Arc<DnsSettings>,
  request_handlers: Vec<Sender<TcpStream>>,
}

impl DnsTcpServer {
  pub fn new(settings: DnsSettings) -> DnsTcpServer {
    Self {
      settings: Arc::new(settings),
      request_handlers: Vec::new(),
    }
  }
}

impl DnsServer for DnsTcpServer {
  fn run(mut self) -> Result<(), Error> {
    let socket = TcpListener::bind(("0.0.0.0", self.settings.listening_port))?;

    for thread_id in 0..self.settings.thread_count {
      let (sender, receiver) = channel();

      self.request_handlers.push(sender);

      let settings = self.settings.clone();

      let _ = Builder::new()
        .name(format!("DnsTcpServer-request-handler-{}", thread_id))
        .spawn(move || loop {
          let mut stream = return_result_or_log_error_continue!(receiver.recv(), "Failed to receive the tcp stream");


          let mut packet_length_buffer = [0; 2];
          ignore_result_or_log_error_continue!(stream.read(&mut packet_length_buffer), "Failed to read the packet length from the stream");

          let mut packet_buffer = Vec::new();
          ignore_result_or_log_error_continue!(stream.read_to_end(&mut packet_buffer), "Failed to read the packet into a buffer");

          let request = return_result_or_log_error_continue!(DnsPacket::from_bytes(packet_buffer.as_slice()), "Failed to parse packet from buffer");
          let resolver = DnsResolver::new(settings.database_file.clone(), settings.remote_lookup_port);

          match resolver.answer_question(request) {
            Ok(result) => {
              ignore_result_or_log_error_continue!(stream.write(result.to_bytes().as_slice()), "Failed writing result back to buffer");
              ignore_result_or_log_error_continue!(stream.shutdown(Shutdown::Both), "Failed shutting down tcp connection");
            }
            Err(error) => {
              log_error!("Resolver error {}", error)
            }
          }
        })?;
    }

    let _ = Builder::new().name("DnsTcpServer-incoming-requests".to_string())
      .spawn(move || for incoming in socket.incoming() {
        match incoming {
          Ok(stream) => ignore_result_and_log_error!(self.request_handlers[random::<usize>() % self.settings.thread_count as usize].send(stream)),
          Err(error) => log_error!("Failed to accept incoming TCP connection: {}", error),
        }
      })?;

    Ok(())
  }
}
