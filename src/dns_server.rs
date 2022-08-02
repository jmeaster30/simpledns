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
  records: HashMap<String, Vec<DnsRecord>>,
}

impl DnsServer {
  pub fn new(listen_port: u16, backup_port: u16, servers: Vec<String>, records: HashMap<String, Vec<DnsRecord>>) -> DnsServer {
    Self {
      listen_port,
      backup_port,
      servers,
      records,
    }
  }

  pub fn run(&mut self, update_receiver: Receiver<(Vec<String>, HashMap<String, Vec<DnsRecord>>)>) -> Result<(), Error> {
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
  
      match self.local_lookup(&question.name, question.query_type) {
        Some(mut records) => {
          packet.question_section.push(question.clone());
          packet.header.question_count += 1;

          if any_record_type(&records, DnsQueryType::DROP) {
            packet.header.response_code = DnsResponseCode::NXDOMAIN;
            println!("dropped :)");
          } else {
            packet.header.response_code = DnsResponseCode::NOERROR;

            let len = records.len() as u16;
            packet.answer_section.append(&mut records);
            packet.header.answer_count += len;
            println!("response packet {:#?}", packet);
            println!("Found records: {:?}", records); 
          }
        }
        None => {
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
        }
      }
    } else {
      println!("Missing question :(");
      packet.header.response_code = DnsResponseCode::FORMERR;
    }  
  
    let response_data = packet.to_bytes();
    //print_hex_bytes(&response_data);
    //println!("Reparsed:\n {:#?}", DnsPacket::from_bytes(response_data.as_slice()));
    socket.send_to(&response_data, src)?;
    Ok(())
  }

  fn lookup(&self, query_name:  &str, query_type: DnsQueryType) -> Result<DnsPacket, Error> {
    let server = (match self.servers.choose(&mut rand::thread_rng()) {
      Some(x) => x.as_str(),
      None => "8.8.8.8"
    }, 53);
    
    self.lookup_internal(query_name, query_type, server)
  } 
  
  fn lookup_internal(&self, query_name: &str, query_type: DnsQueryType, server: (&str, u16)) -> Result<DnsPacket, Error> {
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

  fn recursive_lookup(&self, query_name: &String, query_type: DnsQueryType) -> Option<Vec<DnsRecord>> {
    // pick starting server
    // Loop (infinite?)
    //    send query to name server
    //    if we have answers and noerror then return those records
    //    if we get nxdomain then return that response
    //    Otherwise, we'll try to find a new nameserver based on NS and a corresponding A
    //      record in the additional section. If this succeeds, we can switch name server
    //      and retry the loop.
    //    If not, we'll have to resolve the ip of a NS record. If no NS records exist,
    //      we'll go with what the last server told us.
    //    Here we go down the rabbit hole by starting _another_ lookup sequence in the
    //      midst of our current one. Hopefully, this will give us the IP of an appropriate
    //      name server.
    //    Finally, we pick a random ip from the result, and restart the loop. If no such
    //      record is available, we again return the last result we got.
    None
  }

  fn local_lookup(&self, query_name: &String, query_type: DnsQueryType) -> Option<Vec<DnsRecord>> {
    match self.records.get(query_name) {
      Some(x) => Some(x.clone()),
      None => None
    }
  }
}

fn any_record_type(records: &Vec<DnsRecord>, record_type: DnsQueryType) -> bool {
  for r in records {
    match r {
      DnsRecord::Unknown(x) if x.preamble.query_type == record_type => return true,
      DnsRecord::A(x) if x.preamble.query_type == record_type => return true,
      DnsRecord::NS(x) if x.preamble.query_type == record_type => return true,
      DnsRecord::CNAME(x) if x.preamble.query_type == record_type => return true,
      DnsRecord::MX(x) if x.preamble.query_type == record_type => return true,
      DnsRecord::AAAA(x) if x.preamble.query_type == record_type => return true,
      DnsRecord::DROP(x) if x.preamble.query_type == record_type => return true,
      _ => {}
    }
  }
  false
}

