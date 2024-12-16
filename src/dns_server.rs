extern crate rand;

use std::io::{Error, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::ops::ControlFlow;
use std::sync::{Arc, Condvar, Mutex};
use std::sync::mpsc::{channel, Sender};
use std::thread::Builder;

use rand::random;
use thread_pooler::manager_worker_pool::{ManagerWorkerPool, Worker};

use crate::utils::{get_u16, u16_to_bytes};
use crate::{dns_packet::*, ignore_result_or_log_error_continue_flow, log_debug, return_result_or_log_error_continue_flow};
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

    let mut pool = ManagerWorkerPool::new(self.settings.thread_count);
    pool.set_worker_builder(|| {
      let settings = self.settings.clone();
      let socket_clone = socket.try_clone()?;

      Worker::<(SocketAddr, [u8; 512]), ()>::new(move |receiver| {
        loop {
          let (source, request_buffer) = match receiver.recv() {
            Ok(data) => data,
            Err(error) => {
              log_error!("Failed to receive the tcp stream: {}", error);
              continue;
            }
          };
          let request_packet = match DnsPacket::from_bytes(&request_buffer) {
            Ok(packet) => packet,
            Err(error) => {
              log_error!("There was a problem with parsing the packet :( {}", error);
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
      })
    });

    pool.start_manager(|worker| {
      let socket_clone = match socket.try_clone() {
        Ok(socket) => socket,
        Err(error) => {
          log_error!("Could not clone socket: {}", error);
          return ControlFlow::Break(());
        }
      };
      let mut res: [u8; 512] = [0; 512];
      let (_, src) = match socket.recv_from(&mut res) {
        Ok(x) => x,
        Err(error) => {
          log_error!("There was a problem with reading from the UDP socket :( {}", error);
          return ControlFlow::Continue(())
        }
      };

      match worker.borrow_mut().send((src, res)) {
        Ok(()) => ControlFlow::Continue(()),
        Err(error) => {
          log_error!("Failed sending to worker");
          ControlFlow::Continue(())
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

    let mut pool = ManagerWorkerPool::new(self.settings.thread_count);
    pool.set_worker_builder(|| {
      let settings = self.settings.clone();
      
      Worker::<(TcpStream, SocketAddr), ()>::new(move |receiver| {
        let (mut stream, socket_addr) = return_result_or_log_error_continue_flow!(receiver.recv(), "Failed to receive the tcp stream");
        log_debug!("TCP stream received on {}!!!!!", socket_addr);

        let mut packet_length_buffer = [0; 2];
        ignore_result_or_log_error_continue_flow!(stream.read(&mut packet_length_buffer), "Failed to read the packet length from the stream");
        let packet_length: usize = return_result_or_log_error_continue_flow!(get_u16(&packet_length_buffer, 0), "Failed packet length conversion");

        log_debug!("Read packet length: {:?}", packet_length);
        let mut packet_buffer = vec![0; packet_length];
        log_debug!("Made packet buffer of size {}", packet_buffer.len());
        ignore_result_or_log_error_continue_flow!(stream.read(&mut packet_buffer), "Failed to read the packet into a buffer");

        log_debug!("Done reading to end of the stream");
        let request = return_result_or_log_error_continue_flow!(DnsPacket::from_bytes(&packet_buffer), "Failed to parse packet from buffer");
        let resolver = DnsResolver::new(settings.database_file.clone());

        match resolver.answer_question(request) {
          Ok(result) => {
            log_debug!("Sending response packet: {:#?}", result);
            let response_bytes = result.to_bytes();
            let response_length = response_bytes.len() as u16; // TODO this is a sketchy cast 
            ignore_result_or_log_error_continue_flow!(stream.write(u16_to_bytes(response_length).as_slice()), "Failed writing result back to buffer");
            ignore_result_or_log_error_continue_flow!(stream.write(response_bytes.as_slice()), "Failed writing result back to buffer");
            log_debug!("Flushing Stream Buffer...");
            ignore_result_or_log_error_continue_flow!(stream.flush(), "Failed flushing tcp buffer");
            log_debug!("Shutting down stream...");
            ignore_result_or_log_error_continue_flow!(stream.shutdown(Shutdown::Both), "Failed shutting down tcp connection");
          }
          Err(error) => {
            log_error!("Resolver error {:#?}", error)
          }
        }
        ControlFlow::Continue(())
      })
    });

    pool.start_manager(|worker| {
      let incoming_stream = return_result_or_log_error_continue_flow!(socket.accept(), "Failed accepting incoming tcp connection");
      ignore_result_or_log_error_continue_flow!(worker.borrow_mut().send(incoming_stream), "Failed sending tcp stream to worker");
      ControlFlow::Continue(())
    })?;

    Ok(())
  }
}
