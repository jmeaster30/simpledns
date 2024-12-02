use crate::dns_packet::{DnsPacket, DnsQueryType, DnsQuestion, DnsRecord, DnsResponseCode};
use crate::simple_database::SimpleDatabase;
use crate::{ignore_result_and_log_error, log_debug, log_error, log_info};
use std::error::Error;
use std::net::UdpSocket;

pub struct DnsResolver {
  database: SimpleDatabase,
  remote_lookup_port: u16,
}

impl DnsResolver {
  pub fn new(database_file: String, remote_lookup_port: u16) -> DnsResolver {
    Self {
      database: SimpleDatabase::new(database_file),
      remote_lookup_port,
    }
  }

  pub fn answer_question(&self, request: DnsPacket) -> Result<DnsPacket, Box<dyn Error>> {
    let mut packet = DnsPacket::new();
    packet.header.id = request.header.id;
    packet.header.recurse_desired = true;
    packet.header.recurse_available = true;
    packet.header.query_response = true;

    if let Some(question) = request.question_section.get(0) {
      // TODO make this go through every question in the request
      log_info!("Received question {:?}", question);

      match self
        .database
        .get_records(question.name.clone())
      {
        Ok(mut records) if !records.is_empty() => {
          packet.question_section.push(question.clone());
          packet.header.question_count += 1;

          if DnsResolver::any_record_type(&records, DnsQueryType::DROP) {
            packet.header.response_code = DnsResponseCode::NXDOMAIN;
            log_debug!("dropped :)");
          } else {
            packet.header.response_code = DnsResponseCode::NOERROR;

            let len = records.len() as u16;
            packet.answer_section.append(&mut records);
            packet.header.answer_count += len;
            log_debug!("response packet {:#?}", packet);
            log_debug!("Found records: {:?}", records);
          }
        }
        Ok(_) => self.do_remote_lookup(question, &mut packet)?,
        Err(error) => {
          log_error!("Database error :( {}", error);
          self.do_remote_lookup(question, &mut packet)?;
        }
      }
    } else {
      log_error!("Missing question :(");
      packet.header.response_code = DnsResponseCode::FORMERR;
    }

    Ok(packet)
  }

  fn do_remote_lookup(&self, question: &DnsQuestion, packet: &mut DnsPacket) -> Result<(), Box<dyn Error>> {
    let server = (self.database.get_random_remote_lookup_server().unwrap(), 53);

    let socket = UdpSocket::bind(("0.0.0.0", self.remote_lookup_port))?;

    let mut remote_packet = DnsPacket::new();
    remote_packet.header.recurse_desired = true;
    remote_packet.add_question(DnsQuestion::new(question.name.clone(), question.query_type));
    let remote_packet_bytes = packet.to_bytes();

    socket.send_to(&remote_packet_bytes, server)?;

    let mut res: [u8; 512] = [0; 512];
    socket.recv_from(&mut res)?;

    match DnsPacket::from_bytes(&res) {
      Ok(result) => {
        packet.question_section.push(question.clone());
        packet.header.question_count += 1;
        packet.header.response_code = result.header.response_code;

        for ans in result.answer_section {
          log_debug!("Answer: {:?}", ans);
          packet.answer_section.push(ans.clone());
          ignore_result_and_log_error!(self.database.insert_record(ans, true));
          packet.header.answer_count += 1;
        }

        for auth in result.authority_section {
          log_debug!("Authority: {:?}", auth);
          packet.authority_section.push(auth.clone());
          ignore_result_and_log_error!(self.database.insert_record(auth, true));
          packet.header.authority_count += 1;
        }

        for add in result.additional_section {
          log_debug!("Resource: {:?}", add);
          packet.additional_section.push(add.clone());
          ignore_result_and_log_error!(self.database.insert_record(add, true));
          packet.header.additional_count += 1;
        }
      }
      Err(error) => {
        log_error!("AW CRAP :( {:#?}", error);
        packet.header.response_code = DnsResponseCode::SERVFAIL;
      }
    }
    Ok(())
  }

  /* TODO
  fn recursive_lookup(&self, _query_name: &String, _query_type: DnsQueryType) -> Option<Vec<DnsRecord>> {
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
   */

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
}
