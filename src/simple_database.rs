use crate::dns_packet::{
  DnsQueryType, DnsRecord, DnsRecordA, DnsRecordAAAA, DnsRecordCNAME, DnsRecordDROP, DnsRecordMX,
  DnsRecordNS, DnsRecordPreamble, DnsRecordUnknown,
};
use rusqlite::{Connection, Result};
use std::net::Ipv4Addr;
use std::str;
use std::str::FromStr;

pub struct SimpleDatabase {
  connection: Connection,
}

impl SimpleDatabase {
  pub fn new(database_file: String) -> Self {
    Self {
      connection: Connection::open(database_file).unwrap(),
    }
  }

  pub fn initialize(&self) -> Result<()> {
    self.connection.execute("CREATE TABLE IF NOT EXISTS remote_lookup_servers(ip TEXT PRIMARY KEY)", [])?;
    self.connection.execute("INSERT INTO remote_lookup_servers VALUES (\"8.8.8.8\")", [])?;
    self.connection.execute("INSERT INTO remote_lookup_servers VALUES (\"75.75.75.75\")", [])?;
    self.connection.execute("CREATE TABLE IF NOT EXISTS records(domain TEXT, query_type INTEGER, class INTEGER, ttl INTEGER, len INTEGER, hostipbody TEXT, priority INTEGER, cached INTEGER, insert_time INTEGER)", [])?;
    self.connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS record_unique_idx ON records(domain, query_type, hostipbody, priority, cached)", [])?;
    Ok(())
  }

  pub fn get_records(&self, domain: String, _query_type: DnsQueryType) -> Result<Vec<DnsRecord>> {
    self.connection.execute("DELETE FROM records WHERE records.cached AND records.ttl < unixepoch() - records.insert_time;", [])?;

    // TODO what does query type do?
    let mut stmt = self.connection.prepare("SELECT domain, query_type, class, ttl, len, hostipbody, priority FROM records WHERE domain = ?1;")?;
    let query_results = stmt.query_map(&[&domain], |row| {
      let mut preamble = DnsRecordPreamble::new();
      preamble.domain = row.get(0)?;
      preamble.query_type = DnsQueryType::from_num(row.get(1)?);
      preamble.class = row.get(2)?;
      preamble.ttl = row.get(3)?;
      preamble.len = row.get(4)?;
      Ok(match preamble.query_type {
        DnsQueryType::Unknown(_) => DnsRecord::Unknown(DnsRecordUnknown::new(
          preamble,
          row.get::<usize, String>(5)?.into_bytes(),
        )),
        DnsQueryType::A => DnsRecord::A(DnsRecordA::new(
          preamble,
          Ipv4Addr::from_str(row.get::<usize, String>(5)?.as_str()).unwrap(),
        )),
        DnsQueryType::NS => DnsRecord::NS(DnsRecordNS::new(preamble, row.get::<usize, String>(5)?)),
        DnsQueryType::CNAME => {
          DnsRecord::CNAME(DnsRecordCNAME::new(preamble, row.get::<usize, String>(5)?))
        }
        DnsQueryType::MX => DnsRecord::MX(DnsRecordMX::new(
          preamble,
          row.get::<usize, u16>(5)?,
          row.get::<usize, String>(5)?,
        )),
        DnsQueryType::AAAA => DnsRecord::AAAA(DnsRecordAAAA::new(
          preamble,
          Ipv4Addr::from_str(row.get::<usize, String>(5)?.as_str()).unwrap(),
        )),
        DnsQueryType::DROP => DnsRecord::DROP(DnsRecordDROP::new(preamble)),
      })
    })?;

    let mut results = Vec::new();
    for record in query_results {
      results.push(record?);
    }
    Ok(results)
  }

  pub fn insert_record(&self, record: DnsRecord, cached_record: bool) -> Result<()> {
    let preamble = record.get_preamble();
    let domain = preamble.domain;
    let query_type = preamble.query_type.to_num().to_string();
    let class = preamble.class.to_string();
    let ttl = preamble.ttl.to_string();
    let len = preamble.len.to_string();
    let priority = match &record {
      DnsRecord::Unknown(_) => 0,
      DnsRecord::A(_) => 0,
      DnsRecord::NS(_) => 0,
      DnsRecord::CNAME(_) => 0,
      DnsRecord::MX(mx) => mx.priority,
      DnsRecord::AAAA(_) => 0,
      DnsRecord::DROP(_) => 0,
    }
    .to_string();

    let hostipbody = match &record {
      DnsRecord::Unknown(record) => str::from_utf8(&*record.body).unwrap().to_string(),
      DnsRecord::A(record) => record.ip.to_string(),
      DnsRecord::NS(record) => record.host.clone(),
      DnsRecord::CNAME(record) => record.host.clone(),
      DnsRecord::MX(record) => record.host.clone(),
      DnsRecord::AAAA(record) => record.ip.to_string(),
      DnsRecord::DROP(_) => "".to_string(),
    };

    self.connection.execute(
      "INSERT OR REPLACE INTO records VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, unixepoch());",
      (&domain, &query_type, &class, &ttl, &len, &hostipbody, &priority, &cached_record),
    )?;
    Ok(())
  }

  pub fn get_random_remote_lookup_server(&self) -> Result<String> {
    let mut stmt = self
      .connection
      .prepare("SELECT * FROM remote_lookup_servers ORDER BY RANDOM() LIMIT 1;")?;
    let mut query_results = stmt.query_map([], |row| Ok(row.get(0)?))?;
    query_results.nth(0).unwrap()
  }
}
