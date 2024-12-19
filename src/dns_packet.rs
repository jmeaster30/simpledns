use std::io::{Error, ErrorKind};
use std::net::Ipv4Addr;

use chrono::{Local, DateTime};

#[cfg(feature = "tui")]
use chrono::Duration;

use simple_macros::from;

use crate::utils::{domain_name_to_bytes, get_name_from_packet, get_u16, get_u32, u16_to_bytes, u32_to_bytes};

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
      result.append(&mut a.into());
    }
    for a in &self.authority_section {
      result.append(&mut a.into());
    }
    for a in &self.additional_section {
      result.append(&mut a.into());
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

impl From<DnsOpCode> for u8 {
  fn from(value: DnsOpCode) -> Self {
    match value {
      DnsOpCode::IQUERY => 1,
      DnsOpCode::STATUS => 2,
      DnsOpCode::NOTIFY => 4,
      DnsOpCode::UPDATE => 5,
      DnsOpCode::DNSSO => 6,
      DnsOpCode::QUERY => 0,
    }
  }
}

impl From<u8> for DnsOpCode {
  fn from(value: u8) -> Self {
    match value {
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

impl From<DnsResponseCode> for u8 {
  fn from(value: DnsResponseCode) -> Self {
    match value {
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
}

impl From<u8> for DnsResponseCode {
  fn from(value: u8) -> Self {
    match value {
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
        | ((self.op_code as u8) << 3)
        | ((self.query_response as u8) << 7),
    );
    result.push(
      (self.response_code as u8)
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
        op_code: DnsOpCode::from((bytes[2] >> 3) & 15),
        auth_answer: ((bytes[2] >> 2) & 1) != 0,
        truncated_message: ((bytes[2] >> 1) & 1) != 0,
        recurse_desired: (bytes[2] & 1) != 0,
        recurse_available: ((bytes[3] >> 7) & 1) != 0,
        checking_disabled: ((bytes[3] >> 6) & 1) != 0,
        authed_data: ((bytes[3] >> 7) & 5) != 0,
        z: ((bytes[3] >> 4) & 1) != 0,
        response_code: DnsResponseCode::from(bytes[3] & 15),
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
}

#[from]
fn dns_record_to_vec_u8(value: DnsRecord) -> Vec<u8> {
  match value {
    DnsRecord::Unknown(x) => x.into(),
    DnsRecord::A(x) => x.into(),
    DnsRecord::NS(x) => x.into(),
    DnsRecord::CNAME(x) => x.into(),
    DnsRecord::MX(x) => x.into(),
    DnsRecord::AAAA(x) => x.into(),
    DnsRecord::DROP(_) => Vec::new(),
  }
}

#[from]
#[cfg(feature = "tui")]
fn dns_record_to_ratatui_row(value: DnsRecord) -> ratatui::widgets::Row<'_> {
  match value {
    DnsRecord::Unknown(_) => todo!(),
    DnsRecord::A(dns_record_a) => dns_record_a.into(),
    DnsRecord::NS(dns_record_ns) => dns_record_ns.into(),
    DnsRecord::CNAME(dns_record_cname) => dns_record_cname.into(),
    DnsRecord::MX(dns_record_mx) => dns_record_mx.into(),
    DnsRecord::AAAA(dns_record_aaaa) => dns_record_aaaa.into(),
    DnsRecord::DROP(dns_record_drop) => dns_record_drop.into()
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
}

// FIXME from macro doesn't work :(
impl From<String> for DnsQueryType {
  fn from(value: String) -> Self {
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

// FIXME from macro doesn't work :(
impl From<&str> for DnsQueryType {
  fn from(value: &str) -> Self {
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

impl From<DnsQueryType> for String {
  fn from(value: DnsQueryType) -> Self {
    match value {
      DnsQueryType::Unknown(x) => format!("?? ({})", x),
      DnsQueryType::A => "A".to_string(),
      DnsQueryType::NS => "NS".to_string(),
      DnsQueryType::CNAME => "CNAME".to_string(),
      DnsQueryType::MX => "MX".to_string(),
      DnsQueryType::AAAA => "AAAA".to_string(),
      DnsQueryType::DROP => "DROP".to_string(),
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
}

#[from]
fn dns_record_preamble_to_vec_u8(value: DnsRecordPreamble) -> Vec<u8> {
  let mut result = Vec::new();
  result.append(&mut domain_name_to_bytes(value.domain.as_str()));
  result.append(&mut u16_to_bytes(value.query_type.to_num()));
  result.append(&mut u16_to_bytes(value.class));
  result.append(&mut u32_to_bytes(value.ttl));
  result.append(&mut u16_to_bytes(value.len));
  result
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
}

#[from]
fn dns_record_unknown_to_vec_u8(value: DnsRecordUnknown) -> Vec<u8> {
  let mut result: Vec<u8> = value.preamble.into();
  let mut body_bytes = value.body;
  result.append(&mut body_bytes);
  result
}

#[from]
#[cfg(feature = "tui")]
fn dns_record_unknown_to_ratatui_row(_dns_record_unknown: DnsRecordUnknown) -> ratatui::widgets::Row<'_> {
  todo!()
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

#[from]
#[cfg(feature = "tui")]
fn dns_record_drop_to_ratatui_row(dns_record_drop: DnsRecordDROP) -> ratatui::widgets::Row<'_> {
  ratatui::widgets::Row::new(vec![
    dns_record_drop.preamble.query_type.into(), 
    dns_record_drop.preamble.domain.to_string(),
    "".to_owned(),
    dns_record_drop.preamble.ttl.to_string(),
    "".to_owned(),
    dns_record_drop.preamble.class.to_string(),
  ])
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
}

#[from]
fn dns_record_a_to_vec_u8(value: DnsRecordA) -> Vec<u8> {
  let mut result: Vec<u8> = value.preamble.into();
  result.push(value.ip.octets()[0]);
  result.push(value.ip.octets()[1]);
  result.push(value.ip.octets()[2]);
  result.push(value.ip.octets()[3]);
  result
}

#[from]
#[cfg(feature = "tui")]
fn dns_record_a_to_ratatui_row(dns_record_a: DnsRecordA) -> ratatui::widgets::Row<'_> {
  ratatui::widgets::Row::new(vec![
    dns_record_a.preamble.query_type.into(), 
    dns_record_a.preamble.domain.to_string(),
    dns_record_a.ip.to_string(),
    dns_record_a.preamble.ttl.to_string(),
    "".to_owned(),
    dns_record_a.preamble.class.to_string(),
  ])
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
}

#[from]
fn dns_record_ns_to_vec_u8(dns_record_ns: DnsRecordNS) -> Vec<u8> {
  let mut result: Vec<u8> = dns_record_ns.preamble.into();
  let mut domain_bytes = domain_name_to_bytes(dns_record_ns.host.as_str());
  result.append(&mut domain_bytes);
  result
}

#[from]
#[cfg(feature = "tui")]
fn dns_record_ns_to_ratatui_row(dns_record_ns: DnsRecordNS) -> ratatui::widgets::Row<'_> {
  ratatui::widgets::Row::new(vec![
    dns_record_ns.preamble.query_type.into(), 
    dns_record_ns.preamble.domain.to_string(),
    dns_record_ns.host.to_string(),
    dns_record_ns.preamble.ttl.to_string(),
    "".to_owned(),
    dns_record_ns.preamble.class.to_string(),
  ])
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
}

#[from]
fn dns_record_cname_to_vec_u8(dns_record_cname: DnsRecordCNAME) -> Vec<u8> {
  let mut result: Vec<u8> = dns_record_cname.preamble.into();
  let mut domain_bytes = domain_name_to_bytes(dns_record_cname.host.as_str());
  result.append(&mut domain_bytes);
  result
}

#[from]
#[cfg(feature = "tui")]
fn dns_record_cname_to_ratatui_row(dns_record_cname: DnsRecordCNAME) -> ratatui::widgets::Row<'_> {
  ratatui::widgets::Row::new(vec![
    dns_record_cname.preamble.query_type.into(), 
    dns_record_cname.preamble.domain.to_string(),
    dns_record_cname.host.to_string(),
    dns_record_cname.preamble.ttl.to_string(),
    "".to_owned(),
    dns_record_cname.preamble.class.to_string(),
  ])
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
}

#[from]
fn dns_record_mx_to_vec_u8(dns_record_mx: DnsRecordMX) -> Vec<u8> {
  let mut result: Vec<u8> = dns_record_mx.preamble.into();
  result.append(&mut u16_to_bytes(dns_record_mx.priority));
  let mut domain_bytes = domain_name_to_bytes(dns_record_mx.host.as_str());
  result.append(&mut domain_bytes);
  result
}

#[from]
#[cfg(feature = "tui")]
fn dns_record_mx_to_ratatui_row(dns_record_mx: DnsRecordMX) -> ratatui::widgets::Row<'_> {
  ratatui::widgets::Row::new(vec![
    dns_record_mx.preamble.query_type.into(), 
    dns_record_mx.preamble.domain.to_string(),
    dns_record_mx.host.to_string(),
    dns_record_mx.preamble.ttl.to_string(),
    dns_record_mx.priority.to_string(),
    dns_record_mx.preamble.class.to_string(),
  ])
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
}

#[from]
fn dns_record_aaaa_to_vec_u8(dns_record_aaaa: DnsRecordAAAA) -> Vec<u8> {
  let mut result: Vec<u8> = dns_record_aaaa.preamble.into();
  result.push(dns_record_aaaa.ip.octets()[0]);
  result.push(dns_record_aaaa.ip.octets()[1]);
  result.push(dns_record_aaaa.ip.octets()[2]);
  result.push(dns_record_aaaa.ip.octets()[3]);
  result
}

#[from]
#[cfg(feature = "tui")]
fn from(dns_record_aaaa: DnsRecordAAAA) -> ratatui::widgets::Row<'_> {
  ratatui::widgets::Row::new(vec![
    dns_record_aaaa.preamble.query_type.into(), 
    dns_record_aaaa.preamble.domain.to_string(),
    dns_record_aaaa.ip.to_string(),
    dns_record_aaaa.preamble.ttl.to_string(),
    "".to_owned(),
    dns_record_aaaa.preamble.class.to_string(),
  ])
}

#[derive(Clone)]
pub struct CachedDnsRecord {
  pub cached_time: DateTime<Local>,
  pub record: DnsRecord
}

impl CachedDnsRecord {
  pub fn new(record: DnsRecord, cached_time: DateTime<Local>) -> Self {
    Self {
      cached_time,
      record
    }
  }
}

#[from]
#[cfg(feature = "tui")]
fn cached_dns_record_to_ratatui_row(cached_dns_record: CachedDnsRecord) -> ratatui::widgets::Row<'_> {
  let preamble = cached_dns_record.record.clone().get_preamble();
  let since_insert = Local::now() - cached_dns_record.cached_time;
  let expires_in = Duration::seconds(preamble.ttl.into()) - since_insert;
  ratatui::widgets::Row::new(vec![
    preamble.query_type.into(), 
    preamble.domain.to_string(),
    match &cached_dns_record.record {
      DnsRecord::A(dns_record_a) => dns_record_a.ip.to_string(),
      DnsRecord::NS(dns_record_ns) => dns_record_ns.host.to_string(),
      DnsRecord::CNAME(dns_record_cname) => dns_record_cname.host.to_string(),
      DnsRecord::MX(dns_record_mx) => dns_record_mx.host.to_string(),
      DnsRecord::AAAA(dns_record_aaaa) => dns_record_aaaa.ip.to_string(),
      _ => String::new()
    },
    match &cached_dns_record.record {
      DnsRecord::MX(dns_record_mx) => dns_record_mx.priority.to_string(),
      _ => String::new()
    },
    format!("{} sec", expires_in.num_seconds()),
    preamble.class.to_string(),
  ])
}
