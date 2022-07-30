pub mod dns_packet;

use std::io::Error;
use std::net::UdpSocket;

use crate::dns_packet::*;

fn main() -> Result<(), Error> {
  let qname = "google.com";
  let qtype = DnsQueryType::A;

  let server = ("8.8.8.8", 53);

  let socket = UdpSocket::bind(("0.0.0.0", 43210))?;

  let mut packet = DnsPacket::new();
  packet.header.recurse_desired = true;
  packet.add_question(DnsQuestion::new(qname.to_string(), qtype));
  let packet_bytes = packet.to_bytes();

  socket.send_to(&packet_bytes, server)?;

  let mut res: [u8; 512] = [0; 512];
  socket.recv_from(&mut res)?;

  let response_packet = DnsPacket::from_bytes(&res);
  println!("{:#?}", response_packet);
  Ok(())
}
