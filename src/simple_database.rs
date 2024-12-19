use crate::dns_packet::{
  DnsQueryType, DnsRecord, DnsRecordA, DnsRecordAAAA, DnsRecordCNAME, DnsRecordDROP, DnsRecordMX, DnsRecordNS, DnsRecordPreamble, DnsRecordUnknown
};
#[cfg(feature = "tui")]
use crate::dns_packet::CachedDnsRecord;

#[cfg(feature = "tui")]
use chrono::{Local, TimeZone};
use rusqlite::{params, Connection, Params, Result, Statement, Row};
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
    self.connection.execute("CREATE TABLE IF NOT EXISTS cached_records(domain TEXT, query_type INTEGER, class INTEGER, ttl INTEGER, len INTEGER, hostipbody TEXT, priority INTEGER, insert_time INTEGER)", [])?;
    self.connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS cached_record_unique_idx ON cached_records(domain, query_type, hostipbody, priority)", [])?;
    self.connection.execute("CREATE TABLE IF NOT EXISTS records(domain TEXT, query_type INTEGER, class INTEGER, ttl INTEGER, len INTEGER, hostipbody TEXT, priority INTEGER)", [])?;
    self.connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS record_unique_idx ON records(domain, query_type, hostipbody, priority)", [])?;
    Ok(())
  }

  fn row_to_dns_record(&self, row: &Row<'_>) -> Result<DnsRecord> {
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
  }

  #[cfg(feature = "tui")]
  fn row_to_cached_dns_record(&self, row: &Row<'_>) -> Result<CachedDnsRecord> {
    let record = self.row_to_dns_record(row)?;
    let insert_timestamp = row.get(7)?;
    let insert_time = Local.timestamp_opt(insert_timestamp, 0).unwrap();
    Ok(CachedDnsRecord::new(record, insert_time))
  }

  fn run_dns_record_query<P: Params>(&self, mut statement: Statement<'_>, params: P) -> Result<Vec<DnsRecord>> {
    let query_results = statement.query_map(params, |row| self.row_to_dns_record(row))?;

    let mut results = Vec::new();
    for record in query_results {
      results.push(record?);
    }
    Ok(results)
  }

  #[cfg(feature = "tui")]
  fn run_cached_dns_record_query<P: Params>(&self, mut statement: Statement<'_>, params: P) -> Result<Vec<CachedDnsRecord>> {
    let query_results = statement.query_map(params, |row| self.row_to_cached_dns_record(row))?;

    let mut results = Vec::new();
    for record in query_results {
      results.push(record?);
    }
    Ok(results)
  }

  fn clean_up_cache(&self) -> Result<()> {
    self.connection.execute("DELETE FROM cached_records WHERE cached_records.ttl < unixepoch() - cached_records.insert_time;", [])?;
    Ok(())
  }

  pub fn get_all_records(&self) -> Result<Vec<DnsRecord>> {
    self.clean_up_cache()?;
    let stmt = self.connection.prepare("SELECT domain, query_type, class, ttl, len, hostipbody, priority FROM records;")?;
    self.run_dns_record_query(stmt, params![])
  }

  /* TODO pub fn get_records_where<P: Params>(&self, where_filter: String, params: P) -> Result<Vec<DnsRecord>> {
    self.clean_up_cache()?;
    let stmt = self.connection.prepare(format!("SELECT domain, query_type, class, ttl, len, hostipbody, priority FROM records WHERE {};", where_filter).as_str())?;
    self.run_dns_record_query(stmt, params)
  }*/

  pub fn get_records(&self, domain: String) -> Result<Vec<DnsRecord>> {
    self.clean_up_cache()?;
    let stmt = self.connection.prepare("SELECT domain, query_type, class, ttl, len, hostipbody, priority FROM records WHERE domain = ?1;")?;
    let mut records = self.run_dns_record_query(stmt, params![domain])?;
    let stmt = self.connection.prepare("SELECT domain, query_type, class, ttl, len, hostipbody, priority FROM cached_records WHERE domain = ?1;")?;
    let mut cached_records = self.run_dns_record_query(stmt, params![domain])?;
    records.append(&mut cached_records);
    Ok(records)
  }

  #[cfg(feature = "tui")]
  pub fn get_all_cached_records(&self) -> Result<Vec<CachedDnsRecord>> {
    self.clean_up_cache()?;
    let stmt = self.connection.prepare("SELECT domain, query_type, class, ttl, len, hostipbody, priority, insert_time FROM cached_records;")?;
    self.run_cached_dns_record_query(stmt, params![])
  }

  pub fn insert_record(&self, record: DnsRecord) -> Result<()> {
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
      "INSERT OR REPLACE INTO records VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7);",
      (&domain, &query_type, &class, &ttl, &len, &hostipbody, &priority),
    )?;
    Ok(())
  }

  pub fn insert_cache_record(&self, record: DnsRecord) -> Result<()> {
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
      "INSERT OR REPLACE INTO cached_records VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, unixepoch());",
      (&domain, &query_type, &class, &ttl, &len, &hostipbody, &priority),
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
