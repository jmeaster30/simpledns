extern crate rand;

use std::io::{Error, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, Condvar, Mutex};
use std::sync::mpsc::{channel, Sender};
use std::thread::Builder;

use rand::random;

use crate::utils::{get_u16, u16_to_bytes};
use crate::{dns_packet::*, log_debug};
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
    let bind_addr = ("0.0.0.0", self.settings.listening_port);
    log_debug!("UDP server listening at {:?}:{}", bind_addr.0, bind_addr.1);
    let socket = UdpSocket::bind(bind_addr)?;

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
            let resolver = DnsResolver::new(settings.database_file.clone());
  
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
    let bind_addr = ("0.0.0.0", self.settings.listening_port);
    log_debug!("TCP server listening at {:?}:{}", bind_addr.0, bind_addr.1);
    let socket = TcpListener::bind(bind_addr)?;

    for thread_id in 0..self.settings.thread_count {
      let (sender, receiver) = channel();

      self.request_handlers.push(sender);

      let settings = self.settings.clone();

      let _ = Builder::new()
        .name(format!("DnsTcpServer-request-handler-{}", thread_id))
        .spawn(move || {
          let stream_receiver = receiver;
          loop {
            let mut stream = return_result_or_log_error_continue!(stream_receiver.recv(), "Failed to receive the tcp stream");
            log_debug!("TCP stream received!!!!!");

            let mut packet_length_buffer = [0; 2];
            ignore_result_or_log_error_continue!(stream.read(&mut packet_length_buffer), "Failed to read the packet length from the stream");
            let packet_length: usize = match get_u16(&packet_length_buffer, 0) {
              Ok(x) => x as usize,
              Err(err) => {
                log_error!("Failed packet length conversion: {}", err);
                0 // TODO this feels hacky but the return_result_or_log_error_continue macro wasn't working for some reason also this is very likely to not happen
              }
            };

            log_debug!("Read packet length: {:?}", packet_length);
            let mut packet_buffer = vec![0; packet_length];
            log_debug!("Made packet buffer of size {}", packet_buffer.len());
            ignore_result_or_log_error_continue!(stream.read(&mut packet_buffer), "Failed to read the packet into a buffer");

            log_debug!("Done reading to end of the stream");
            let request = return_result_or_log_error_continue!(DnsPacket::from_bytes(&packet_buffer), "Failed to parse packet from buffer");
            let resolver = DnsResolver::new(settings.database_file.clone());

            match resolver.answer_question(request) {
              Ok(result) => {
                log_debug!("Sending response packet: {:#?}", result);
                let response_bytes = result.to_bytes();
                let response_length = response_bytes.len() as u16; // TODO this is a sketchy cast 
                ignore_result_or_log_error_continue!(stream.write(u16_to_bytes(response_length).as_slice()), "Failed writing result back to buffer");
                ignore_result_or_log_error_continue!(stream.write(response_bytes.as_slice()), "Failed writing result back to buffer");
                log_debug!("Flushing Stream Buffer...");
                ignore_result_or_log_error_continue!(stream.flush(), "Failed flushing tcp buffer");
                log_debug!("Shutting down stream...");
                ignore_result_or_log_error_continue!(stream.shutdown(Shutdown::Both), "Failed shutting down tcp connection");
              }
              Err(error) => {
                log_error!("Resolver error {:#?}", error)
              }
            }
          }
        })?;
    }

    let _ = Builder::new().name("DnsTcpServer-incoming-requests".to_string())
      .spawn(move || for incoming in socket.incoming() {
        match incoming {
          Ok(stream) => {
            let idx = random::<usize>() % self.settings.thread_count as usize;
            log_debug!("Picked handler {}/{}", idx, self.settings.thread_count);
            ignore_result_and_log_error!(self.request_handlers[idx].send(stream))
          }
          Err(error) => log_error!("Failed to accept incoming TCP connection: {}", error),
        }
      })?;

    Ok(())
  }
}
