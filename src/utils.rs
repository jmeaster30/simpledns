use std::io::{Error, ErrorKind};

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
