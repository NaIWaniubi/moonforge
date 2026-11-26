// evidence: a small, deterministic schema for auditable binary facts.

///|
/// Artifact identity. Empty input has no digest and is marked as such.
pub(all) struct Artifact {
  path : String
  size : Int64
  sha256 : String?
  format : String
  parse_status : String
} derive(Debug)

///|
/// Where a fact came from. RVAs and VAs are zero when a format does not use
/// them; file_offset is always the byte offset in the artifact.
pub(all) struct Location {
  section : String
  rva : Int64
  va : Int64
  file_offset : Int64
  size : Int64
} derive(Debug)

///|
/// One fact. `status` is one of parsed, derived, malformed, unsupported,
/// empty. `attributes` is a sorted list of stable key/value pairs.
pub(all) struct Fact {
  id : String
  kind : String
  source : String
  location : Location
  status : String
  attributes : Array[(String, String)]
} derive(Debug)

///|
/// A diagnostic is separate from a fact: errors never become zero-valued
/// successful facts.
pub(all) struct Diagnostic {
  code : String
  severity : String
  message : String
  location : Location?
} derive(Debug)

///|
/// Complete evidence envelope for one artifact.
pub(all) struct EvidenceReport {
  schema_version : String
  artifact : Artifact
  facts : Array[Fact]
  diagnostics : Array[Diagnostic]
  stats : Array[(String, String)]
} derive(Debug)

///|
fn hex_nibble(v : Int32) -> Char {
  if v < 10 {
    (48 + v).unsafe_to_char()
  } else {
    (97 + v - 10).unsafe_to_char()
  }
}

///|
/// SHA-256 hex digest. Empty bytes intentionally return the standard empty
/// digest so callers can distinguish "hashed empty input" from "no digest".
pub fn sha256_hex(data : Bytes) -> String {
  let bytes = @crypto.sha256(data)
  let out : Array[Char] = []
  for i = 0; i < bytes.length(); i = i + 1 {
    let b = bytes[i].to_int() & 0xFF
    out.push(hex_nibble(b >> 4))
    out.push(hex_nibble(b & 0xF))
  }
  String::from_array(out)
}

///|
/// Build an artifact envelope. `parse_status` is supplied by the adapter and
/// must be explicit; this function never invents success.
pub fn artifact(
  path : String,
  data : Bytes,
  format : String,
  parse_status : String,
) -> Artifact {
  {
    path,
    size: data.length().to_int64(),
    sha256: if data.length() == 0 {
      None
    } else {
      Some(sha256_hex(data))
    },
    format,
    parse_status,
  }
}

///|
/// Empty location for facts that are artifact-wide.
pub fn no_location() -> Location {
  { section: "", rva: 0L, va: 0L, file_offset: 0L, size: 0L, }
}

///|
/// Construct a fact with a deterministic id seed.
pub fn fact(
  id : String,
  kind : String,
  source : String,
  location : Location,
  status : String,
  attributes : Array[(String, String)],
) -> Fact {
  { id, kind, source, location, status, attributes, }
}

///|
/// Construct a diagnostic.
pub fn diagnostic(
  code : String,
  severity : String,
  message : String,
  location : Location?,
) -> Diagnostic {
  { code, severity, message, location, }
}

///|
fn jstr(s : String) -> String {
  let out : Array[Char] = ['"']
  for c in s {
    let v = c.to_int()
    if v == 34 {
      out.push('\\')
      out.push('"')
    } else if v == 92 {
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
  out.push('"')
  String::from_array(out)
}

///|
fn jopt(s : String?) -> String {
  match s {
    Some(value) => jstr(value)
    None => "null"
  }
}

///|
fn jloc(loc : Location) -> String {
  "{\"section\":" +
  jstr(loc.section) +
  ",\"rva\":" +
  loc.rva.to_string() +
  ",\"va\":" +
  loc.va.to_string() +
  ",\"file_offset\":" +
  loc.file_offset.to_string() +
  ",\"size\":" +
  loc.size.to_string() +
  "}"
}

///|
fn jlocopt(loc : Location?) -> String {
  match loc {
    Some(value) => jloc(value)
    None => "null"
  }
}

///|
fn jpairs(pairs : Array[(String, String)]) -> String {
  let parts : Array[String] = []
  for pair in pairs {
    parts.push(jstr(pair.0) + ":" + jstr(pair.1))
  }
  "{" + parts.join(",") + "}"
}

///|
fn jfact(f : Fact) -> String {
  "{\"id\":" +
  jstr(f.id) +
  ",\"kind\":" +
  jstr(f.kind) +
  ",\"source\":" +
  jstr(f.source) +
  ",\"location\":" +
  jloc(f.location) +
  ",\"status\":" +
  jstr(f.status) +
  ",\"attributes\":" +
  jpairs(f.attributes) +
  "}"
}

///|
fn jdiag(d : Diagnostic) -> String {
  "{\"code\":" +
  jstr(d.code) +
  ",\"severity\":" +
  jstr(d.severity) +
  ",\"message\":" +
  jstr(d.message) +
  ",\"location\":" +
  jlocopt(d.location) +
  "}"
}

///|
/// Canonical JSON. Arrays preserve caller order; callers must sort facts and
/// diagnostics when byte-for-byte determinism matters.
pub fn EvidenceReport::to_json(self : EvidenceReport) -> String {
  let facts : Array[String] = []
  for f in self.facts {
    facts.push(jfact(f))
  }
  let diags : Array[String] = []
  for d in self.diagnostics {
    diags.push(jdiag(d))
  }
  let stats : Array[String] = []
  for pair in self.stats {
    stats.push(jstr(pair.0) + ":" + jstr(pair.1))
  }
  "{\"schema_version\":" +
  jstr(self.schema_version) +
  ",\"artifact\":{\"path\":" +
  jstr(self.artifact.path) +
  ",\"size\":" +
  self.artifact.size.to_string() +
  ",\"sha256\":" +
  jopt(self.artifact.sha256) +
  ",\"format\":" +
  jstr(self.artifact.format) +
  ",\"parse_status\":" +
  jstr(self.artifact.parse_status) +
  "},\"facts\":[" +
  facts.join(",") +
  "],\"diagnostics\":[" +
  diags.join(",") +
  "],\"stats\":{" +
  stats.join(",") +
  "}}"
}
