use std::net::Ipv4Addr;

#[derive(Clone, Debug)]
pub struct DnsPacket {
  pub header: DnsHeader,
  pub question_section: Vec<DnsQuestion>,
  pub answer_section: Vec<DnsRecord>,
  pub authority_section: Vec<DnsRecord>,
  pub additional_section: Vec<DnsRecord>,
}

impl DnsPacket {
  pub fn from_bytes(buffer: &[u8]) -> DnsPacket {
    let header = DnsHeader::new(&buffer[0..12]);
    let mut packet = Self { 
      header: header.clone(), 
      question_section: Vec::new(), 
      answer_section: Vec::new(),
      authority_section: Vec::new(),
      additional_section: Vec::new()
    };
    
    let mut buffer_index = 12;
    for _ in 0..header.question_count {
      let mut question = DnsQuestion::new();
      (question.name, buffer_index) = get_name_from_packet(buffer, buffer_index, 0);
      question.query_type = DnsQueryType::from_num(((buffer[buffer_index] as u16) << 8) | (buffer[buffer_index + 1] as u16));
      buffer_index += 2;
      question.class = ((buffer[buffer_index] as u16) << 8) | (buffer[buffer_index + 1] as u16);
      packet.question_section.push(question);
    }

    packet
  }
}

#[derive(Clone, Debug)]
pub enum DnsOpCode {
  QUERY = 0,
  IQUERY = 1,
  STATUS = 2,
  NOTIFY = 4,
  UPDATE = 5,
  DNSSO = 6,
}

impl DnsOpCode {
  pub fn from_num(num: u8) -> DnsOpCode {
    match num {
      0 | _ => DnsOpCode::QUERY,
      1 => DnsOpCode::IQUERY,
      2 => DnsOpCode::STATUS,
      4 => DnsOpCode::NOTIFY,
      5 => DnsOpCode::UPDATE,
      6 => DnsOpCode::DNSSO,
    }
  }
}

#[derive(Clone, Debug)]
pub enum DnsResponseCode {
  NOERROR = 0,
  FORMERR = 1,
  SERVFAIL = 2,
  NXDOMAIN = 3,
  NOTIMP = 4,
  REFUSED = 5,
  YXDOMAIN = 6,
  YXRRSET = 7,
  NXRRSET = 8,
  NOTAUTH = 9,
  NOTZONE = 10,
  DSOTYPENI = 11,
}

impl DnsResponseCode {
  pub fn from_num(num: u8) -> DnsResponseCode {
    match num {
      0  => DnsResponseCode::NOERROR,
      1 | _ => DnsResponseCode::FORMERR,
      2 => DnsResponseCode::SERVFAIL,
      3 => DnsResponseCode::NXDOMAIN,
      4 => DnsResponseCode::NOTIMP,
      5 => DnsResponseCode::REFUSED,
      6 => DnsResponseCode::YXDOMAIN,
      7 => DnsResponseCode::YXRRSET,
      8 => DnsResponseCode::NXRRSET,
      9 => DnsResponseCode::NOTAUTH,
      10 => DnsResponseCode::NOTZONE,
      11 => DnsResponseCode::DSOTYPENI,
    }
  }
}

#[derive(Clone, Debug)]
pub struct DnsHeader {
  pub id: u16,
  pub query_response: bool,
  pub op_code: DnsOpCode,
  pub auth_answer: bool,
  pub truncated_message: bool,
  pub recurse_desired: bool,
  pub recurse_available: bool,
  pub checking_disabled: bool,
  pub authed_data: bool,
  pub z: bool,
  pub response_code: DnsResponseCode,
  pub question_count: u16,
  pub answer_count: u16,
  pub authority_count: u16,
  pub additional_count: u16,
}

impl DnsHeader {
  pub fn new(bytes: &[u8]) -> Self {
    Self {
      id: ((bytes[0] as u16) << 8) | bytes[1] as u16,
      query_response: ((bytes[2] >> 7) & 1) != 0,
      op_code: DnsOpCode::from_num((bytes[2] >> 3) & 15),
      auth_answer: ((bytes[2] >> 2) & 1) != 0,
      truncated_message: ((bytes[2] >> 1) & 1) != 0,
      recurse_desired: (bytes[2] & 1) != 0,
      recurse_available: ((bytes[3] >> 7) & 1) != 0,
      checking_disabled: ((bytes[3] >> 6) & 1) != 0,
      authed_data: ((bytes[3] >> 7) & 5) != 0,
      z: ((bytes[3] >> 4) & 1) != 0,
      response_code: DnsResponseCode::from_num(bytes[3] & 15),
      question_count: ((bytes[4] as u16) << 8) | bytes[5] as u16,
      answer_count: ((bytes[6] as u16) << 8) | bytes[7] as u16,
      authority_count: ((bytes[8] as u16) << 8) | bytes[9] as u16,
      additional_count: ((bytes[10] as u16) << 8) | bytes[11] as u16,
    }
  }
}

#[derive(Clone, Debug)]
pub struct DnsQuestion {
  pub name: String,
  pub query_type: DnsQueryType,
  pub class: u16,
}

impl DnsQuestion {
    pub fn new() -> Self { Self { name: "".to_string(), query_type: DnsQueryType::Unknown(0), class: 0 } }
}

#[derive(Clone, Debug)]
pub enum DnsRecord {
  Unknown(DnsRecordUnknown),
  A(DnsRecordA),
}

#[derive(Clone, Debug)]
pub enum DnsQueryType {
  Unknown(u16),
  A,
}

impl DnsQueryType {
  pub fn from_num(num: u16) -> DnsQueryType {
    match num {
      1 => DnsQueryType::A,
      x => DnsQueryType::Unknown(x),
    }
  }
}

#[derive(Clone, Debug)]
pub struct DnsRecordPreamble {
  pub domain: String,
  pub query_type: DnsQueryType,
  pub class: u16,
  pub ttl: u32,
  pub len: u16,
}

#[derive(Clone, Debug)]
pub struct DnsRecordUnknown {
  pub preamble: DnsRecordPreamble,
  pub body: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct DnsRecordA {
  pub preamble: DnsRecordPreamble,
  pub ip: Ipv4Addr,
}

pub fn get_name_from_packet(bytes: &[u8], start: usize, depth: i32) -> (String, usize) {
  if depth == 20 {
    return ("".to_string(), start);
  }
  
  let mut result = "".to_string();
  let mut index = start;
  loop {
    let length_byte = bytes[index];
    if (length_byte & 0xC0) == 0xC0 {
      //jump
      let offset_byte = bytes[index + 1] as u16;
      index += 2;

      let jump_index = (((length_byte as u16) ^ 0xC0) << 8) | offset_byte;
      let (part, _) = get_name_from_packet(bytes, jump_index as usize, depth + 1);
      result.push_str(part.as_str());
      break;
    } else {
      index += 1;
      if length_byte == 0 {
        break;
      }

      result.push_str(".");
      let end = index + (length_byte as usize);
      println!("{} {}", index, length_byte as usize);
      result.push_str(String::from_utf8(bytes[index..end].to_vec()).unwrap().to_lowercase().as_str());
      index = end;
    }
  }
  (result, index)
} 

pub fn print_hex(bytes: String) {
  for i in bytes.as_bytes() {
    print!("{:02X} ", i);
  }
  println!();
}

pub fn string_to_label_seq(value: &str) -> Vec<u8> {
  let splits = value.split('.');
  let mut result = Vec::new();
  for s in splits {
    let length = s.len();
    result.push((length & 0xFF) as u8);
    for b in s.as_bytes() {
      result.push(b.clone());
    }
  }
  result.push(0x00);
  result
}

pub fn label_seq_to_string(value: Vec<u8>) -> String {
  "".to_string()
}
