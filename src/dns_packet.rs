use std::io::{Error, ErrorKind};
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
  pub fn new() -> DnsPacket {
    Self {
      header: DnsHeader::new(),
      question_section: Vec::new(),
      answer_section: Vec::new(),
      authority_section: Vec::new(),
      additional_section: Vec::new(),
    }
  }

  pub fn add_question(&mut self, question: DnsQuestion) {
    self.question_section.push(question);
    self.header.question_count += 1;
  }

  pub fn add_answer(&mut self, answer: DnsRecord) {
    self.answer_section.push(answer);
    self.header.answer_count += 1;
  }

  pub fn to_bytes(&self) -> Vec<u8> {
    let mut result = Vec::new();
    result.append(&mut self.header.to_bytes());
    for q in &self.question_section {
      result.append(&mut q.to_bytes());
    }
    for a in &self.answer_section {
      result.append(&mut a.to_bytes());
    }
    for a in &self.authority_section {
      result.append(&mut a.to_bytes());
    }
    for a in &self.additional_section {
      result.append(&mut a.to_bytes());
    }
    result
  }

  pub fn from_bytes(buffer: &[u8]) -> Result<DnsPacket, Error> {
    let header = DnsHeader::from_bytes(&buffer[0..12])?;
    let mut packet = Self {
      header: header.clone(),
      question_section: Vec::new(),
      answer_section: Vec::new(),
      authority_section: Vec::new(),
      additional_section: Vec::new(),
    };

    let mut buffer_index = 12;
    for _ in 0..header.question_count {
      let mut question = DnsQuestion::empty();
      (question.name, buffer_index) = get_name_from_packet(buffer, buffer_index, 0)?;
      question.query_type = DnsQueryType::from_num(get_u16(buffer, buffer_index)?);
      buffer_index += 2;
      question.class = get_u16(buffer, buffer_index)?;
      buffer_index += 2;

      packet.question_section.push(question);
    }

    for _ in 0..header.answer_count {
      let record;
      (record, buffer_index) = parse_dns_record(buffer, buffer_index)?;
      packet.answer_section.push(record);
    }

    for _ in 0..header.authority_count {
      let record;
      (record, buffer_index) = parse_dns_record(buffer, buffer_index)?;
      packet.authority_section.push(record);
    }

    for _ in 0..header.additional_count {
      let record;
      (record, buffer_index) = parse_dns_record(buffer, buffer_index)?;
      packet.additional_section.push(record);
    }

    Ok(packet)
  }
}

fn parse_dns_record(buffer: &[u8], buffer_index: usize) -> Result<(DnsRecord, usize), Error> {
  let mut index = buffer_index;
  let mut record_preamble = DnsRecordPreamble::new();
  (record_preamble.domain, index) = get_name_from_packet(buffer, index, 0)?;
  record_preamble.query_type = DnsQueryType::from_num(get_u16(buffer, index)?);
  index += 2;
  record_preamble.class = get_u16(buffer, index)?;
  index += 2;
  record_preamble.ttl = get_u32(buffer, index)?;
  index += 4;
  record_preamble.len = get_u16(buffer, index)?;
  index += 2;

  let data_len = record_preamble.len as usize;

  match record_preamble.query_type {
    DnsQueryType::Unknown(_) => {
      let body = &buffer[index..(index + data_len)];
      index += data_len;
      Ok((
        DnsRecord::Unknown(DnsRecordUnknown::new(record_preamble, body.to_vec())),
        index,
      ))
    }
    DnsQueryType::A => {
      let addr = Ipv4Addr::new(
        buffer[index],
        buffer[index + 1],
        buffer[index + 2],
        buffer[index + 3],
      );
      index += 4;
      Ok((DnsRecord::A(DnsRecordA::new(record_preamble, addr)), index))
    }
    DnsQueryType::NS => {
      let domain;
      (domain, index) = get_name_from_packet(buffer, index, 0)?;
      Ok((
        DnsRecord::NS(DnsRecordNS::new(record_preamble, domain)),
        index,
      ))
    }
    DnsQueryType::CNAME => {
      let domain;
      (domain, index) = get_name_from_packet(buffer, index, 0)?;
      Ok((
        DnsRecord::CNAME(DnsRecordCNAME::new(record_preamble, domain)),
        index,
      ))
    }
    DnsQueryType::MX => {
      let priority = get_u16(buffer, index)?;
      index += 2;
      let domain;
      (domain, index) = get_name_from_packet(buffer, index, 0)?;
      Ok((
        DnsRecord::MX(DnsRecordMX::new(record_preamble, priority, domain)),
        index,
      ))
    }
    DnsQueryType::AAAA => {
      let addr = Ipv4Addr::new(
        buffer[index],
        buffer[index + 1],
        buffer[index + 2],
        buffer[index + 3],
      );
      index += 4;
      Ok((
        DnsRecord::AAAA(DnsRecordAAAA::new(record_preamble, addr)),
        index,
      ))
    }
    DnsQueryType::DROP => Err(Error::new(ErrorKind::InvalidData, "Stop")),
  }
}

#[derive(Copy, Clone, Debug)]
pub enum DnsOpCode {
  QUERY = 0,
  IQUERY = 1,
  STATUS = 2,
  NOTIFY = 4,
  UPDATE = 5,
  DNSSO = 6,
}

impl DnsOpCode {
  pub fn to_num(&self) -> u8 {
    match self {
      DnsOpCode::IQUERY => 1,
      DnsOpCode::STATUS => 2,
      DnsOpCode::NOTIFY => 4,
      DnsOpCode::UPDATE => 5,
      DnsOpCode::DNSSO => 6,
      DnsOpCode::QUERY => 0,
    }
  }

  pub fn from_num(num: u8) -> DnsOpCode {
    match num {
      1 => DnsOpCode::IQUERY,
      2 => DnsOpCode::STATUS,
      4 => DnsOpCode::NOTIFY,
      5 => DnsOpCode::UPDATE,
      6 => DnsOpCode::DNSSO,
      0 | _ => DnsOpCode::QUERY,
    }
  }
}

#[derive(Copy, Clone, Debug)]
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
  pub fn to_num(&self) -> u8 {
    match self {
      DnsResponseCode::NOERROR => 0,
      DnsResponseCode::FORMERR => 1,
      DnsResponseCode::SERVFAIL => 2,
      DnsResponseCode::NXDOMAIN => 3,
      DnsResponseCode::NOTIMP => 4,
      DnsResponseCode::REFUSED => 5,
      DnsResponseCode::YXDOMAIN => 6,
      DnsResponseCode::YXRRSET => 7,
      DnsResponseCode::NXRRSET => 8,
      DnsResponseCode::NOTAUTH => 9,
      DnsResponseCode::NOTZONE => 10,
      DnsResponseCode::DSOTYPENI => 11,
    }
  }

  pub fn from_num(num: u8) -> DnsResponseCode {
    match num {
      0 => DnsResponseCode::NOERROR,
      1 => DnsResponseCode::FORMERR,
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
      _ => DnsResponseCode::NOERROR, // TODOfigure out the right error code
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
  pub fn new() -> Self {
    Self {
      id: rand::random::<u16>(),
      query_response: false,
      op_code: DnsOpCode::QUERY,
      auth_answer: false,
      truncated_message: false,
      recurse_desired: false,
      recurse_available: false,
      checking_disabled: false,
      authed_data: false,
      z: false,
      response_code: DnsResponseCode::NOERROR,
      question_count: 0,
      answer_count: 0,
      authority_count: 0,
      additional_count: 0,
    }
  }

  pub fn to_bytes(&self) -> Vec<u8> {
    let mut result = Vec::new();

    result.append(&mut u16_to_bytes(self.id));
    result.push(
      (self.recurse_desired as u8)
        | ((self.truncated_message as u8) << 1)
        | ((self.auth_answer as u8) << 2)
        | ((self.op_code.to_num()) << 3)
        | ((self.query_response as u8) << 7),
    );
    result.push(
      (self.response_code.to_num())
        | ((self.checking_disabled as u8) << 4)
        | ((self.authed_data as u8) << 5)
        | ((self.z as u8) << 6)
        | ((self.recurse_available as u8) << 7),
    );
    result.append(&mut u16_to_bytes(self.question_count));
    result.append(&mut u16_to_bytes(self.answer_count));
    result.append(&mut u16_to_bytes(self.authority_count));
    result.append(&mut u16_to_bytes(self.additional_count));

    result
  }

  pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
    if bytes.len() == 12 {
      Ok(Self {
        id: get_u16(bytes, 0)?,
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
        question_count: get_u16(bytes, 4)?,
        answer_count: get_u16(bytes, 6)?,
        authority_count: get_u16(bytes, 8)?,
        additional_count: get_u16(bytes, 10)?,
      })
    } else {
      Err(Error::new(
        ErrorKind::InvalidData,
        "Not enough bytes for header",
      ))
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
  pub fn new(name: String, query_type: DnsQueryType) -> Self {
    Self {
      name,
      query_type,
      class: 1,
    }
  }

  pub fn to_bytes(&self) -> Vec<u8> {
    let mut result = Vec::new();

    result.append(&mut domain_name_to_bytes(self.name.as_str()));
    result.append(&mut u16_to_bytes(self.query_type.to_num()));
    result.append(&mut u16_to_bytes(self.class));

    result
  }

  pub fn empty() -> Self {
    Self {
      name: "".to_string(),
      query_type: DnsQueryType::Unknown(0),
      class: 0,
    }
  }
}

#[derive(Clone, Debug)]
pub enum DnsRecord {
  Unknown(DnsRecordUnknown),
  A(DnsRecordA),
  NS(DnsRecordNS),
  CNAME(DnsRecordCNAME),
  MX(DnsRecordMX),
  AAAA(DnsRecordAAAA),
  DROP(DnsRecordDROP),
}

impl DnsRecord {
  pub fn get_query_type(&self) -> DnsQueryType {
    match self {
      DnsRecord::Unknown(x) => x.preamble.query_type,
      DnsRecord::A(x) => x.preamble.query_type,
      DnsRecord::NS(x) => x.preamble.query_type,
      DnsRecord::CNAME(x) => x.preamble.query_type,
      DnsRecord::MX(x) => x.preamble.query_type,
      DnsRecord::AAAA(x) => x.preamble.query_type,
      DnsRecord::DROP(x) => x.preamble.query_type,
    }
  }

  pub fn get_preamble(&self) -> DnsRecordPreamble {
    match self {
      DnsRecord::Unknown(x) => x.preamble.clone(),
      DnsRecord::A(x) => x.preamble.clone(),
      DnsRecord::NS(x) => x.preamble.clone(),
      DnsRecord::CNAME(x) => x.preamble.clone(),
      DnsRecord::MX(x) => x.preamble.clone(),
      DnsRecord::AAAA(x) => x.preamble.clone(),
      DnsRecord::DROP(x) => x.preamble.clone(),
    }
  }

  pub fn to_bytes(&self) -> Vec<u8> {
    match self {
      DnsRecord::Unknown(x) => x.to_bytes(),
      DnsRecord::A(x) => x.to_bytes(),
      DnsRecord::NS(x) => x.to_bytes(),
      DnsRecord::CNAME(x) => x.to_bytes(),
      DnsRecord::MX(x) => x.to_bytes(),
      DnsRecord::AAAA(x) => x.to_bytes(),
      DnsRecord::DROP(_) => Vec::new(),
    }
  }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum DnsQueryType {
  Unknown(u16),
  A,
  NS,
  CNAME,
  MX,
  AAAA,
  DROP,
}

impl DnsQueryType {
  pub fn to_num(&self) -> u16 {
    match self {
      DnsQueryType::Unknown(x) => *x,
      DnsQueryType::A => 1,
      DnsQueryType::NS => 2,
      DnsQueryType::CNAME => 5,
      DnsQueryType::MX => 15,
      DnsQueryType::AAAA => 28,
      DnsQueryType::DROP => 666,
    }
  }

  pub fn from_num(num: u16) -> DnsQueryType {
    match num {
      1 => DnsQueryType::A,
      2 => DnsQueryType::NS,
      5 => DnsQueryType::CNAME,
      15 => DnsQueryType::MX,
      28 => DnsQueryType::AAAA,
      666 => DnsQueryType::DROP,
      x => DnsQueryType::Unknown(x),
    }
  }

  pub fn from_string(value: &str) -> DnsQueryType {
    match value.to_uppercase().as_str() {
      "A" => DnsQueryType::A,
      "NS" => DnsQueryType::NS,
      "CNAME" => DnsQueryType::CNAME,
      "MX" => DnsQueryType::MX,
      "AAAA" => DnsQueryType::AAAA,
      "DROP" => DnsQueryType::DROP,
      _ => DnsQueryType::Unknown(0),
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

impl DnsRecordPreamble {
  pub fn new() -> Self {
    Self {
      domain: String::new(),
      query_type: DnsQueryType::Unknown(0),
      class: 0,
      ttl: 0,
      len: 0,
    }
  }

  pub fn build(domain: String, query_type: DnsQueryType, class: u16, ttl: u32) -> Self {
    Self {
      domain,
      query_type,
      class,
      ttl,
      len: 0
    }
  }

  pub fn to_bytes(&self) -> Vec<u8> {
    let mut result = Vec::new();

    result.append(&mut domain_name_to_bytes(self.domain.as_str()));
    result.append(&mut u16_to_bytes(self.query_type.to_num()));
    result.append(&mut u16_to_bytes(self.class));
    result.append(&mut u32_to_bytes(self.ttl));
    result.append(&mut u16_to_bytes(self.len));

    result
  }
}

#[derive(Clone, Debug)]
pub struct DnsRecordUnknown {
  pub preamble: DnsRecordPreamble,
  pub body: Vec<u8>,
}

impl DnsRecordUnknown {
  pub fn new(mut preamble: DnsRecordPreamble, body: Vec<u8>) -> Self {
    preamble.len = body.len() as u16;
    Self { preamble, body }
  }

  pub fn to_bytes(&self) -> Vec<u8> {
    let mut result = Vec::new();

    result.append(&mut self.preamble.to_bytes());
    let mut body_bytes = self.body.clone();
    result.append(&mut body_bytes);

    result
  }
}

#[derive(Clone, Debug)]
pub struct DnsRecordDROP {
  pub preamble: DnsRecordPreamble,
}

impl DnsRecordDROP {
  pub fn new(preamble: DnsRecordPreamble) -> Self {
    Self { preamble }
  }
}

#[derive(Clone, Debug)]
pub struct DnsRecordA {
  pub preamble: DnsRecordPreamble,
  pub ip: Ipv4Addr,
}

impl DnsRecordA {
  pub fn new(mut preamble: DnsRecordPreamble, ip: Ipv4Addr) -> Self {
    preamble.len = 4;
    Self { preamble, ip }
  }

  pub fn to_bytes(&self) -> Vec<u8> {
    let mut result = Vec::new();

    result.append(&mut self.preamble.to_bytes());
    result.push(self.ip.octets()[0]);
    result.push(self.ip.octets()[1]);
    result.push(self.ip.octets()[2]);
    result.push(self.ip.octets()[3]);

    result
  }
}

#[derive(Clone, Debug)]
pub struct DnsRecordNS {
  pub preamble: DnsRecordPreamble,
  pub host: String,
}

impl DnsRecordNS {
  pub fn new(mut preamble: DnsRecordPreamble, host: String) -> Self {
    let len = domain_name_to_bytes(host.as_str()).len();
    preamble.len = len as u16;
    Self { preamble, host }
  }

  pub fn to_bytes(&self) -> Vec<u8> {
    let mut result = Vec::new();

    result.append(&mut self.preamble.to_bytes());
    result.append(&mut domain_name_to_bytes(self.host.as_str()));

    result
  }
}

#[derive(Clone, Debug)]
pub struct DnsRecordCNAME {
  pub preamble: DnsRecordPreamble,
  pub host: String,
}

impl DnsRecordCNAME {
  pub fn new(mut preamble: DnsRecordPreamble, host: String) -> Self {
    let len = domain_name_to_bytes(host.as_str()).len() as u16;
    preamble.len = len;
    Self { preamble, host }
  }

  pub fn to_bytes(&self) -> Vec<u8> {
    let mut result = Vec::new();

    result.append(&mut self.preamble.to_bytes());
    result.append(&mut domain_name_to_bytes(self.host.as_str()));

    result
  }
}

#[derive(Clone, Debug)]
pub struct DnsRecordMX {
  pub preamble: DnsRecordPreamble,
  pub priority: u16,
  pub host: String,
}

impl DnsRecordMX {
  pub fn new(mut preamble: DnsRecordPreamble, priority: u16, host: String) -> Self {
    let len = domain_name_to_bytes(host.as_str()).len() + 2;
    preamble.len = len as u16;
    Self {
      preamble: preamble.clone(),
      priority,
      host,
    }
  }

  pub fn to_bytes(&self) -> Vec<u8> {
    let mut result = Vec::new();

    result.append(&mut self.preamble.to_bytes());
    result.append(&mut u16_to_bytes(self.priority));
    result.append(&mut domain_name_to_bytes(self.host.as_str()));

    result
  }
}

#[derive(Clone, Debug)]
pub struct DnsRecordAAAA {
  pub preamble: DnsRecordPreamble,
  pub ip: Ipv4Addr,
}

impl DnsRecordAAAA {
  pub fn new(mut preamble: DnsRecordPreamble, ip: Ipv4Addr) -> Self {
    preamble.len = 4;
    Self { preamble, ip }
  }

  pub fn to_bytes(&self) -> Vec<u8> {
    let mut result = Vec::new();

    result.append(&mut self.preamble.to_bytes());
    result.push(self.ip.octets()[0]);
    result.push(self.ip.octets()[1]);
    result.push(self.ip.octets()[2]);
    result.push(self.ip.octets()[3]);

    result
  }
}

pub fn domain_name_to_bytes(value: &str) -> Vec<u8> {
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

pub fn get_name_from_packet(
  bytes: &[u8],
  start: usize,
  depth: i32,
) -> Result<(String, usize), Error> {
  if depth == 20 {
    return Err(Error::new(ErrorKind::InvalidData, "Loop limit exceeded"));
  }

  let mut result = "".to_string();
  let mut index = start;
  let mut delim = "";
  loop {
    let length_byte = bytes[index];
    if (length_byte & 0xC0) == 0xC0 {
      let offset_byte = bytes[index + 1] as u16;
      index += 2;

      let jump_index = (((length_byte as u16) ^ 0xC0) << 8) | offset_byte;
      let (part, _) = get_name_from_packet(bytes, jump_index as usize, depth + 1)?;
      result.push_str(part.as_str());
      break;
    } else {
      index += 1;
      if length_byte == 0 {
        break;
      }

      result.push_str(delim);
      delim = ".";
      let end = index + (length_byte as usize);
      result.push_str(
        String::from_utf8(bytes[index..end].to_vec())
          .unwrap()
          .to_lowercase()
          .as_str(),
      );
      index = end;
    }
  }
  Ok((result, index))
}

pub fn u16_to_bytes(num: u16) -> Vec<u8> {
  vec![((num >> 8) & 0xFF) as u8, (num & 0xFF) as u8]
}

pub fn u32_to_bytes(num: u32) -> Vec<u8> {
  vec![
    ((num >> 24) & 0xFF) as u8,
    ((num >> 16) & 0xFF) as u8,
    ((num >> 8) & 0xFF) as u8,
    (num & 0xFF) as u8,
  ]
}

pub fn get_u16(bytes: &[u8], index: usize) -> Result<u16, Error> {
  if index <= bytes.len() - 2 {
    Ok((bytes[index] as u16) << 8 | (bytes[index + 1] as u16))
  } else {
    Err(Error::new(
      ErrorKind::InvalidData,
      "Not enough bytes to get a u16",
    ))
  }
}

pub fn get_u32(bytes: &[u8], index: usize) -> Result<u32, Error> {
  if index <= bytes.len() - 4 {
    Ok(
      (bytes[index] as u32) << 24
        | (bytes[index + 1] as u32) << 16
        | (bytes[index + 2] as u32) << 8
        | (bytes[index + 3] as u32),
    )
  } else {
    Err(Error::new(
      ErrorKind::InvalidData,
      "Not enough bytes to get a u32",
    ))
  }
}

pub fn print_hex(bytes: String) {
  for i in bytes.as_bytes() {
    print!("{:02X} ", i);
  }
  println!();
}

pub fn print_hex_bytes(bytes: &Vec<u8>) {
  for i in bytes {
    print!("{:02X} ", i);
  }
  println!();
}
