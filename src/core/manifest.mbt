// manifest: format detection, per-file summary, canonical JSON.
// JSON here is deliberately narrow: it parses exactly the shape this tool
// writes. It is not a general JSON parser and does not pretend to be one.

///|
fn be32(data : Bytes, at : Int32) -> Int32 {
  (data[at].to_int() << 24) |
  (data[at + 1].to_int() << 16) |
  (data[at + 2].to_int() << 8) |
  data[at + 3].to_int()
}

///|
/// Container detection from the leading bytes only. Order matters: MZ before
/// anything else, then ELF magic, then the four Mach-O magics plus the fat
/// header, then WASM magic/version, then XML/binary plist. Everything else is
/// Unknown and is never handed to a parser.
pub fn detect_format(data : Bytes) -> Format {
  let n = data.length()
  if n >= 2 && data[0].to_int() == 0x4D && data[1].to_int() == 0x5A {
    return Pe
  }
  if n >= 4 &&
    data[0].to_int() == 0x7F &&
    data[1].to_int() == 0x45 &&
    data[2].to_int() == 0x4C &&
    data[3].to_int() == 0x46 {
    return Elf
  }
  if n >= 4 {
    let magic = be32(data, 0)
    if magic == 0xFEEDFACE ||
      magic == 0xFEEDFACF ||
      magic == 0xCEFAEDFE ||
      magic == 0xCFFAEDFE ||
      magic == 0xCAFEBABE ||
      magic == 0xBEBAFECA {
      return MachO
    }
  }
  if n >= 8 &&
    data[0].to_int() == 0x00 &&
    data[1].to_int() == 0x61 &&
    data[2].to_int() == 0x73 &&
    data[3].to_int() == 0x6D &&
    data[4].to_int() == 0x01 &&
    data[5].to_int() == 0x00 &&
    data[6].to_int() == 0x00 &&
    data[7].to_int() == 0x00 {
    return Wasm
  }
  if data.has_prefix(b"bplist00"[:]) ||
    data.has_prefix(b"<?xml"[:]) ||
    data.has_prefix(b"<plist"[:]) {
    return Plist
  }
  Unknown
}

///|
fn wasm_ints(data : Bytes) -> Array[Int32] {
  let out : Array[Int32] = []
  for b in data {
    out.push(b.to_int())
  }
  out
}

///|
fn summarize(data : Bytes, format : Format) -> (Summary, String) {
  match format {
    Pe =>
      match @pe.parse(data) {
        Ok(pe) =>
          (
            {
              sections: pe.sections.length(),
              symbols: pe.symbols.length(),
              imports: pe.imports.length(),
              exports: pe.exports.length(),
            },
            "parsed",
          )
        Err(_) => (Summary::empty(), "malformed")
      }
    Elf =>
      match @elf.parse(data) {
        Ok(elf) =>
          (
            {
              sections: elf.sections.length(),
              symbols: elf.symbols.length(),
              imports: elf.imports.length(),
              exports: elf.exports.length(),
            },
            "parsed",
          )
        Err(_) => (Summary::empty(), "malformed")
      }
    MachO =>
      match @macho.parse(data) {
        Ok(m) =>
          (
            {
              sections: m.sections.length(),
              symbols: m.symbols.length(),
              imports: m.imports.length(),
              exports: m.exports.length(),
            },
            "parsed",
          )
        Err(_) => (Summary::empty(), "malformed")
      }
    Wasm =>
      match @wasm_inspect.parse_module(wasm_ints(data)) {
        Ok(parsed) =>
          match @wasm_inspect.decode_module(parsed) {
            Ok(decoded) =>
              (
                {
                  sections: parsed.sections().length(),
                  symbols: 0,
                  imports: decoded.imports().length(),
                  exports: decoded.exports().length(),
                },
                "parsed",
              )
            Err(_) => (Summary::empty(), "malformed")
          }
        Err(_) => (Summary::empty(), "malformed")
      }
    Plist =>
      try {
        let _ = @moonplist.decode(data)
        (Summary::empty(), "parsed")
      } catch {
        _ => (Summary::empty(), "malformed")
      }
    Unknown =>
      (
        Summary::empty(),
        if data.length() == 0 {
          "empty"
        } else {
          "unsupported"
        },
      )
  }
}

///|
fn hex_nibble(v : Int32) -> Char {
  if v < 10 {
    (48 + v).unsafe_to_char()
  } else {
    (97 + v - 10).unsafe_to_char()
  }
}

///|
fn hex_value(c : UInt16) -> Int32? {
  let v = c.to_int()
  if v >= 48 && v <= 57 {
    Some(v - 48)
  } else if v >= 97 && v <= 102 {
    Some(v - 87)
  } else if v >= 65 && v <= 70 {
    Some(v - 55)
  } else {
    None
  }
}

///|
pub fn hex_of_bytes(bytes : FixedArray[Byte]) -> String {
  let out : Array[Char] = []
  for i = 0; i < bytes.length(); i = i + 1 {
    let b = bytes[i].to_int() & 0xFF
    out.push(hex_nibble(b >> 4))
    out.push(hex_nibble(b & 0xF))
  }
  String::from_array(out)
}

///|
/// One file to one record. Empty input has no digest (`None`), because
/// hashing nothing and calling the result a file identity would be a lie.
pub fn record_of_bytes(path : String, data : Bytes) -> FileRecord {
  let format = detect_format(data)
  let (summary, parse_status) = summarize(data, format)
  {
    path,
    format,
    size: data.length().to_int64(),
    sha256: if data.length() == 0 {
      None
    } else {
      Some(hex_of_bytes(@crypto.sha256(data)))
    },
    summary,
    parse_status,
  }
}

// ─── JSON out ────────────────────────────────────────────────────────────────

///|
fn escape_json(s : String) -> String {
  let out : Array[Char] = []
  for c in s {
    let v = c.to_int()
    if c.to_int() == 34 {
      out.push('\\')
      out.push('"')
    } else if c == '\\' {
      out.push('\\')
      out.push('\\')
    } else if v == 10 {
      out.push('\\')
      out.push('n')
    } else if v == 13 {
      out.push('\\')
      out.push('r')
    } else if v == 9 {
      out.push('\\')
      out.push('t')
    } else if v < 0x20 {
      // Non-printable control characters go out as \u00XX.
      out.push('\\')
      out.push('u')
      out.push('0')
      out.push('0')
      out.push(hex_nibble((v >> 4) & 0xF))
      out.push(hex_nibble(v & 0xF))
    } else {
      out.push(c)
    }
  }
  String::from_array(out)
}

///|
fn record_to_json(r : FileRecord) -> String {
  let digest = match r.sha256 {
    Some(d) => "\"" + d + "\""
    None => "null"
  }
  "{\"path\":\"" +
  escape_json(r.path) +
  "\",\"format\":\"" +
  r.format.label() +
  "\",\"size\":" +
  r.size.to_string() +
  ",\"sha256\":" +
  digest +
  ",\"parse_status\":\"" +
  escape_json(r.parse_status) +
  "\",\"summary\":{\"sections\":" +
  r.summary.sections.to_string() +
  ",\"symbols\":" +
  r.summary.symbols.to_string() +
  ",\"imports\":" +
  r.summary.imports.to_string() +
  ",\"exports\":" +
  r.summary.exports.to_string() +
  "}}"
}

///|
pub fn Manifest::to_json(self : Manifest) -> String {
  let parts : Array[String] = []
  for r in self.files {
    parts.push(record_to_json(r))
  }
  "{\"files\":[" + parts.join(",") + "]}"
}

// ─── JSON in (narrow) ────────────────────────────────────────────────────────
// Parses the canonical shape above. Tolerates whitespace between tokens and
// key reordering; refuses anything else with a message naming the field.

///|
fn skip_ws(s : String, at : Int32) -> Int32 {
  let mut i = at
  while i < s.length() {
    let c = s[i]
    if c == ' ' || c == '\n' || c == '\r' || c == '\t' {
      i = i + 1
    } else {
      break
    }
  }
  i
}

///|
/// Index just past the string starting at `at` (which must be '"'), plus the
/// decoded value. Returns None when the string is unterminated.
fn read_string(s : String, at : Int32) -> (String, Int32)? {
  if at >= s.length() || s[at].to_int() != 34 {
    return None
  }
  let out : Array[Char] = []
  let mut i = at + 1
  while i < s.length() {
    let c = s[i]
    let cv = c.to_int()
    if cv == 34 {
      return Some((String::from_array(out), i + 1))
    }
    if cv == 92 && i + 1 < s.length() {
      let e = s[i + 1]
      let ev = e.to_int()
      if ev == 34 || ev == 92 || ev == 47 {
        out.push(e.unsafe_to_char())
        i = i + 2
        continue
      }
      if ev == 110 {
        out.push('\n')
      } else if ev == 114 {
        out.push('\r')
      } else if ev == 116 {
        out.push('\t')
      } else if ev == 117 {
        // Our writer only emits \u00XX for control characters. Decode exactly
        // that range; anything wider is refused rather than guessed.
        if i + 5 < s.length() {
          let h0 = hex_value(s[i + 2])
          let h1 = hex_value(s[i + 3])
          let h2 = hex_value(s[i + 4])
          let h3 = hex_value(s[i + 5])
          match (h0, h1, h2, h3) {
            (Some(a), Some(b), Some(c), Some(d)) => {
              let v = (a << 12) | (b << 8) | (c << 4) | d
              if v < 0x20 {
                out.push(v.unsafe_to_char())
                i = i + 6
                continue
              }
            }
            _ => ()
          }
        }
        return None
      } else {
        return None
      }
      i = i + 2
      continue
    }
    out.push(c.unsafe_to_char())
    i = i + 1
  }
  None
}

///|
fn read_int(s : String, at : Int32) -> (Int64, Int32)? {
  let mut i = at
  let mut neg = false
  if i < s.length() && s[i].to_int() == 45 {
    neg = true
    i = i + 1
  }
  let start = i
  while i < s.length() && s[i].to_int() >= 48 && s[i].to_int() <= 57 {
    i = i + 1
  }
  if i == start {
    return None
  }
  let digits = s[start:i].to_owned()
  let mut v : Int64 = 0L
  for c in digits {
    v = v * 10L + (c.to_int() - 48).to_int64()
  }
  if neg {
    v = 0L - v
  }
  Some((v, i))
}

///|
fn read_format(s : String, at : Int32) -> (Format, Int32)? {
  match read_string(s, at) {
    Some((label, next)) =>
      match Format::from_label(label) {
        Some(f) => Some((f, next))
        None => None
      }
    None => None
  }
}

///|
/// Read the object body of one file record starting at `{`. Returns the record
/// and the index just past its closing `}`.
fn read_record(s : String, at : Int32) -> (FileRecord, Int32)? {
  let mut i = skip_ws(s, at)
  if i >= s.length() || s[i].to_int() != 123 {
    return None
  }
  i = skip_ws(s, i + 1)
  let mut path : String? = None
  let mut format : Format? = None
  let mut size : Int64? = None
  let mut digest : String? = None
  let mut summary : Summary? = None
  let mut parse_status : String? = None
  while i < s.length() && s[i].to_int() != 125 {
    // key
    let (key, after_key) = match read_string(s, i) {
      Some(pair) => pair
      None => return None
    }
    i = skip_ws(s, after_key)
    if i >= s.length() || s[i].to_int() != 58 {
      return None
    }
    i = skip_ws(s, i + 1)
    if key == "path" {
      let (v, next) = match read_string(s, i) {
        Some(pair) => pair
        None => return None
      }
      path = Some(v)
      i = next
    } else if key == "format" {
      let (v, next) = match read_format(s, i) {
        Some(pair) => pair
        None => return None
      }
      format = Some(v)
      i = next
    } else if key == "size" {
      let (v, next) = match read_int(s, i) {
        Some(pair) => pair
        None => return None
      }
      size = Some(v)
      i = next
    } else if key == "sha256" {
      if i + 3 < s.length() && s[i:i + 4].to_owned() == "null" {
        digest = None
        i = i + 4
      } else {
        let (v, next) = match read_string(s, i) {
          Some(pair) => pair
          None => return None
        }
        digest = Some(v)
        i = next
      }
    } else if key == "parse_status" {
      let (v, next) = match read_string(s, i) {
        Some(pair) => pair
        None => return None
      }
      parse_status = Some(v)
      i = next
    } else if key == "summary" {
      let (v, next) = match read_summary(s, i) {
        Some(pair) => pair
        None => return None
      }
      summary = Some(v)
      i = next
    } else {
      return None
    }
    i = skip_ws(s, i)
    if i < s.length() && s[i].to_int() == 44 {
      i = skip_ws(s, i + 1)
    }
  }
  if i >= s.length() || s[i].to_int() != 125 {
    return None
  }
  match (path, format, size, summary) {
    (Some(p), Some(f), Some(sz), Some(sm)) => {
      let status = match parse_status {
        Some(value) => value
        None => "legacy"
      }
      Some(
        (
          {
            path: p,
            format: f,
            size: sz,
            sha256: digest,
            summary: sm,
            parse_status: status,
          },
          i + 1,
        ),
      )
    }
    _ => None
  }
}

///|
fn read_summary(s : String, at : Int32) -> (Summary, Int32)? {
  let mut i = skip_ws(s, at)
  if i >= s.length() || s[i].to_int() != 123 {
    return None
  }
  i = skip_ws(s, i + 1)
  let mut sections : Int32? = None
  let mut symbols : Int32? = None
  let mut imports : Int32? = None
  let mut exports : Int32? = None
  while i < s.length() && s[i].to_int() != 125 {
    let (key, after_key) = match read_string(s, i) {
      Some(pair) => pair
      None => return None
    }
    i = skip_ws(s, after_key)
    if i >= s.length() || s[i].to_int() != 58 {
      return None
    }
    i = skip_ws(s, i + 1)
    let (v, next) = match read_int(s, i) {
      Some(pair) => pair
      None => return None
    }
    if key == "sections" {
      sections = Some(v.to_int())
    } else if key == "symbols" {
      symbols = Some(v.to_int())
    } else if key == "imports" {
      imports = Some(v.to_int())
    } else if key == "exports" {
      exports = Some(v.to_int())
    } else {
      return None
    }
    i = skip_ws(s, next)
    if i < s.length() && s[i].to_int() == 44 {
      i = skip_ws(s, i + 1)
    }
  }
  if i >= s.length() || s[i].to_int() != 125 {
    return None
  }
  match (sections, symbols, imports, exports) {
    (Some(a), Some(b), Some(c), Some(d)) =>
      Some(({ sections: a, symbols: b, imports: c, exports: d, }, i + 1))
    _ => None
  }
}

///|
pub fn Manifest::from_json(text : String) -> Result[Manifest, String] {
  let mut i = skip_ws(text, 0)
  if i >= text.length() || text[i].to_int() != 123 {
    return Err("manifest: expected '{'")
  }
  i = skip_ws(text, i + 1)
  let (key, after_key) = match read_string(text, i) {
    Some(pair) => pair
    None => return Err("manifest: expected key")
  }
  if key != "files" {
    return Err("manifest: expected \"files\"")
  }
  i = skip_ws(text, after_key)
  if i >= text.length() || text[i].to_int() != 58 {
    return Err("manifest: expected ':'")
  }
  i = skip_ws(text, i + 1)
  if i >= text.length() || text[i].to_int() != 91 {
    return Err("manifest: expected '['")
  }
  i = skip_ws(text, i + 1)
  let files : Array[FileRecord] = []
  while i < text.length() && text[i].to_int() != 93 {
    let (rec, next) = match read_record(text, i) {
      Some(pair) => pair
      None => return Err("manifest: bad file record at offset " + i.to_string())
    }
    files.push(rec)
    i = skip_ws(text, next)
    if i < text.length() && text[i].to_int() == 44 {
      i = skip_ws(text, i + 1)
    }
  }
  if i >= text.length() || text[i].to_int() != 93 {
    return Err("manifest: expected ']'")
  }
  Ok({ files, })
}
