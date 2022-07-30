extern crate rand;

use std::io::{Error, ErrorKind};
use std::net::UdpSocket;
use std::collections::HashMap;
use std::sync::mpsc::{Receiver, TryRecvError};

use rand::seq::SliceRandom;

use crate::dns_packet::*;

pub struct DnsServer {
  listen_port: u16,
  backup_port: u16,
  servers: Vec<String>,
  records: HashMap<String, DnsRecord>,
}

impl DnsServer {
  pub fn new(listen_port: u16, backup_port: u16, servers: Vec<String>, records: HashMap<String, DnsRecord>) -> DnsServer {
    Self {
      listen_port,
      backup_port,
      servers,
      records,
    }
  }

  pub fn run(&mut self, update_receiver: Receiver<(Vec<String>, HashMap<String, DnsRecord>)>) -> Result<(), Error> {
    let socket = UdpSocket::bind(("0.0.0.0", self.listen_port))?;
    socket.set_nonblocking(true)?;

    let mut update_receiver_disconnected = false;

    loop {
      if !update_receiver_disconnected {
        match update_receiver.try_recv() {
          Ok(message) => {
            println!("message: {:#?}", message);
            self.servers = message.0;
            self.records = message.1;
            println!("Servers: {:#?}", self.servers);
          },
          Err(TryRecvError::Empty) => {
            // empty queue do nothing
            //println!("empty file update queue")
          },
          Err(TryRecvError::Disconnected) => {
            update_receiver_disconnected = true;
            println!("WARNING!!!!! Update Receiver Has Disconnected (this may be okay but may be bad)");
          }
        }
      }
      match self.handle_query(&socket) {
        Ok(_) => {println!("Done with query :)")},
        Err(e) if e.kind() == ErrorKind::WouldBlock => {},
        Err(e) => println!("An error occurred: {}", e),
      }
    }
  }

  fn handle_query(&self, socket: &UdpSocket) -> Result<(), Error> {
    let mut res: [u8; 512] = [0; 512];
    let (_, src) = socket.recv_from(&mut res)?;
    println!("done receive");
    let mut request = DnsPacket::from_bytes(&res)?;
  
    let mut packet = DnsPacket::new();
    packet.header.id = request.header.id;
    packet.header.recurse_desired = true;
    packet.header.recurse_available = true;
    packet.header.query_response = true;
  
    if let Some(question) = request.question_section.get(0) {
      // TODO make this go through every question in the request
      println!("Received question {:?}", question);
  
      match self.lookup(&question.name, question.query_type) {
        Ok(result) => {
          packet.question_section.push(question.clone());
          packet.header.question_count += 1;
          packet.header.response_code = result.header.response_code;
    
          for ans in result.answer_section {
            println!("Answer: {:?}", ans);
            packet.answer_section.push(ans);
            packet.header.answer_count += 1;
          }
    
          for auth in result.authority_section {
            println!("Authority: {:?}", auth);
            packet.authority_section.push(auth);
            packet.header.authority_count += 1;
          }
    
          for add in result.additional_section {
            println!("Resource: {:?}", add);
            packet.additional_section.push(add);
            packet.header.additional_count += 1;
          }
        }
        Err(error) => {
          println!("AW CRAP :( {:#?}", error);
          packet.header.response_code = DnsResponseCode::SERVFAIL;
        }
      }
    } else {
      println!("Missing question :(");
      packet.header.response_code = DnsResponseCode::FORMERR;
    }
  
    let response_data = packet.to_bytes();
    socket.send_to(&response_data, src)?;
    Ok(())
  }
  
  fn lookup(&self, query_name: &str, query_type: DnsQueryType) -> Result<DnsPacket, Error> {
    let server = (match self.servers.choose(&mut rand::thread_rng()) {
      Some(x) => x.as_str(),
      None => "8.8.8.8"
    }, 53);
    println!("here {}", server.0);
  
    let socket = UdpSocket::bind(("0.0.0.0", self.backup_port))?;
    println!("okay here");
  
    let mut packet = DnsPacket::new();
    packet.header.recurse_desired = true;
    packet.add_question(DnsQuestion::new(query_name.to_string(), query_type));
    let packet_bytes = packet.to_bytes();
  
    print_hex_bytes(&packet_bytes);
  
    socket.send_to(&packet_bytes, server)?;
    println!("send");
  
    let mut res: [u8; 512] = [0; 512];
    socket.recv_from(&mut res)?;
    println!("get");
  
    DnsPacket::from_bytes(&res)
  }
}


