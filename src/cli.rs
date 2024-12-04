use std::error::Error;
use std::io::{stdin, stdout, Write};
use std::net::Ipv4Addr;

use std::str::FromStr;

use tabled::{builder::Builder, settings::Style};

use crate::{log_info, log_debug};
use crate::{dns_packet::{DnsQueryType, DnsRecord, DnsRecordA, DnsRecordAAAA, DnsRecordCNAME, DnsRecordDROP, DnsRecordMX, DnsRecordNS, DnsRecordPreamble}, settings::DnsSettings, simple_database::SimpleDatabase, RecordArgs, RecordFilters};

pub fn add_record(args: RecordArgs, settings: DnsSettings) -> Result<(), Box<dyn Error>> {
  let domain = args.domain.unwrap();
  let query_type = args.query_type.unwrap().into();
  let preamble = DnsRecordPreamble::build(domain.clone(), query_type, args.class, args.ttl);
  let record = match query_type {
    DnsQueryType::Unknown(_) => panic!("Impossible state"),
    DnsQueryType::A => DnsRecord::A(DnsRecordA::new(preamble, Ipv4Addr::from_str(args.ip.unwrap().as_str()).expect("Couldn't parse ipv4 address"))),
    DnsQueryType::NS => DnsRecord::NS(DnsRecordNS::new(preamble, args.host.unwrap())),
    DnsQueryType::CNAME => DnsRecord::CNAME(DnsRecordCNAME::new(preamble, args.host.unwrap())),
    DnsQueryType::MX => DnsRecord::MX(DnsRecordMX::new(preamble, args.priority.unwrap(), args.host.unwrap())),
    DnsQueryType::AAAA => DnsRecord::AAAA(DnsRecordAAAA::new(preamble, Ipv4Addr::from_str(args.ip.unwrap().as_str()).expect("Couldn't parse ipv4 address"))),
    DnsQueryType::DROP => DnsRecord::DROP(DnsRecordDROP::new(preamble)),
  };
  let database = SimpleDatabase::new(settings.database_file);
  database.insert_record(record.clone())?;
  log_debug!("Successfully added record: {:?}", record);
  log_info!("Successfully added record [{:?}] {}", query_type, domain);
  Ok(())
}

pub fn add_record_interactive(settings: DnsSettings) -> Result<(), Box<dyn Error>> {
  let domain = get_input("Domain: ", None, "A domain is required.", |x| !x.is_empty());
  let query_type = DnsQueryType::from_string(get_input("Record Type: ",
                              None,
                              "A record type is required [A, NS, CNAME, MX, AAAA, DROP]",
                              |x| ["A", "NS", "CNAME", "MX", "AAAA", "DROP"].contains(&x.to_uppercase().as_str())).as_str());
  let class = get_input("Class [default 1]: ",
                          Some("1".to_string()),
                          "A valid u16 must be supplied.",
                          |x| !x.is_empty() && x.parse::<u16>().is_ok()).parse::<u16>().unwrap();
  let ttl = get_input("TTL [default 300]: ",
                        Some("300".to_string()),
                        "A valid u32 must be supplied.",
                        |x| !x.is_empty() && x.parse::<u32>().is_ok()).parse::<u32>().unwrap();
  let preamble = DnsRecordPreamble::build(domain, query_type, class, ttl);
  let record = match query_type {
    DnsQueryType::Unknown(_) => panic!("Impossible state"),
    DnsQueryType::A => {
      let ip = get_input("IP: ", None, "A valid ip address is required.", |x| Ipv4Addr::from_str(x.as_str()).is_ok());
      DnsRecord::A(DnsRecordA::new(preamble, Ipv4Addr::from_str(ip.as_str()).unwrap()))
    }
    DnsQueryType::NS => {
      let host = get_input("Host: ", None, "A host is required.", |x| !x.is_empty());
      DnsRecord::NS(DnsRecordNS::new(preamble, host))
    }
    DnsQueryType::CNAME => {
      let host = get_input("Host: ", None, "A host is required.", |x| !x.is_empty());
      DnsRecord::CNAME(DnsRecordCNAME::new(preamble, host))
    }
    DnsQueryType::MX => {
      let host = get_input("Host: ", None, "A host is required.", |x| !x.is_empty());
      let priority = get_input("Priority: ", None, "A valid u16 priority is required.", |x| !x.is_empty() && x.parse::<u16>().is_ok()).parse::<u16>().unwrap();
      DnsRecord::MX(DnsRecordMX::new(preamble, priority, host))
    }
    DnsQueryType::AAAA => {
      let ip = get_input("IP: ", None, "A valid ip address is required.", |x| Ipv4Addr::from_str(x.as_str()).is_ok());
      DnsRecord::AAAA(DnsRecordAAAA::new(preamble, Ipv4Addr::from_str(ip.as_str()).unwrap()))
    }
    DnsQueryType::DROP => DnsRecord::DROP(DnsRecordDROP::new(preamble))
  };
  let database = SimpleDatabase::new(settings.database_file);
  database.insert_record(record.clone())?;
  log_info!("Successfully added record: {:?}", record);
  Ok(())
}

fn get_input(message: &str, default_value: Option<String>, error_message: &str, validate: fn(String) -> bool) -> String {
  loop {
    let mut s = String::new();
    print!("{}", message);
    let _ = stdout().flush();
    let _ = stdin().read_line(&mut s).expect("Did not enter a correct string");
    s = s.trim_matches(&['\r', '\n', ' ', '\t']).to_string();
    if validate(s.clone()) {
      return s;
    } else if let Some(value) = default_value.clone() {
      return value;
    }
    println!("{}", error_message);
  }
}

fn print_table(records: Vec<DnsRecord>) {
  let mut builder = Builder::new();
  builder.push_record(["Type", "Domain", "Host/IP", "Priority", "TTL", "Class"]);
  for record in records {
    builder.push_record(match record {
      DnsRecord::Unknown(dns_record_unknown) => [
        dns_record_unknown.preamble.query_type.into(),
        dns_record_unknown.preamble.domain,
        "".to_owned(),
        "".to_owned(),
        dns_record_unknown.preamble.ttl.to_string(),
        dns_record_unknown.preamble.class.to_string()
      ],
      DnsRecord::A(dns_record_a) => [
        dns_record_a.preamble.query_type.into(),
        dns_record_a.preamble.domain,
        dns_record_a.ip.to_string(),
        "".to_owned(),
        dns_record_a.preamble.ttl.to_string(),
        dns_record_a.preamble.class.to_string()
      ],
      DnsRecord::NS(dns_record_ns) => [
        dns_record_ns.preamble.query_type.into(),
        dns_record_ns.preamble.domain,
        dns_record_ns.host,
        "".to_owned(),
        dns_record_ns.preamble.ttl.to_string(),
        dns_record_ns.preamble.class.to_string()
      ],
      DnsRecord::CNAME(dns_record_cname) => [
        dns_record_cname.preamble.query_type.into(),
        dns_record_cname.preamble.domain,
        dns_record_cname.host,
        "".to_owned(),
        dns_record_cname.preamble.ttl.to_string(),
        dns_record_cname.preamble.class.to_string()
      ],
      DnsRecord::MX(dns_record_mx) => [
        dns_record_mx.preamble.query_type.into(),
        dns_record_mx.preamble.domain,
        dns_record_mx.host,
        dns_record_mx.priority.to_string(),
        dns_record_mx.preamble.ttl.to_string(),
        dns_record_mx.preamble.class.to_string()
      ],
      DnsRecord::AAAA(dns_record_aaaa) => [
        dns_record_aaaa.preamble.query_type.into(),
        dns_record_aaaa.preamble.domain,
        dns_record_aaaa.ip.to_string(),
        "".to_owned(),
        dns_record_aaaa.preamble.ttl.to_string(),
        dns_record_aaaa.preamble.class.to_string()
      ],
      DnsRecord::DROP(dns_record_drop) => [
        dns_record_drop.preamble.query_type.into(),
        dns_record_drop.preamble.domain,
        "".to_owned(),
        "".to_owned(),
        dns_record_drop.preamble.ttl.to_string(),
        dns_record_drop.preamble.class.to_string()
      ],
    });
  }
  let mut table = builder.build();
  table.with(Style::empty());
  println!("{}", table.to_string())
}

pub fn list_records<'a>(settings: DnsSettings, filters: RecordFilters) -> Result<(), Box<dyn Error>> {
  let database = SimpleDatabase::new(settings.database_file);
  let records = database.get_all_records()?;
  
  // TODO make the filtering happen in the database
  let mut filtered_records = Vec::new();
  for record in records {
    match &filters.query_type {
      Some(query_type) if record.get_query_type() != query_type.clone().into() => break,
      _ => {}
    };
    match &filters.domain {
      Some(domain) if record.get_preamble().domain != *domain => break,
      _ => {}
    };
    match &filters.class {
      Some(class) if record.get_preamble().class != *class => break,
      _ => {}
    };
    match &filters.ttl {
      Some(ttl) if record.get_preamble().ttl != *ttl => break,
      _ => {}
    };
    match &filters.priority {
      Some(priority) => match record {
        DnsRecord::MX(mx) if mx.priority != *priority => break,
        _ => {}
      }
      _ => {}
    };
    match &filters.ip {
      Some(ip) => match record {
        DnsRecord::A(a) if a.ip != Ipv4Addr::from_str(ip.as_str())? => break,
        DnsRecord::AAAA(aaaa) if aaaa.ip != Ipv4Addr::from_str(ip.as_str())? => break,
        _ => {}
      }
      _ => {}
    };
    match &filters.host {
      Some(host) => match record {
        DnsRecord::CNAME(cname) if cname.host != *host => break,
        DnsRecord::MX(mx) if mx.host != *host => break,
        DnsRecord::NS(ns) if ns.host != *host => break,
        _ => {}
      }
      _ => {}
    }
    filtered_records.push(record);
  }

  print_table(filtered_records);
  Ok(())
}
