// bundle: join a Mach-O image and an optional Info.plist into one honest
// profile. Missing or malformed inputs are reported, never guessed.

///|
/// Top-level plist facts that matter for app identity.
pub struct PlistSummary {
  keys : Array[String]
  bundle_id : String?
  version : String?
} derive(Debug)

///|
/// Combined app-bundle profile.
pub struct BundleReport {
  macho_format : String
  plist : PlistSummary?
  note : String
} derive(Debug)

///|
fn text_value(value : @moonplist.Value?) -> String? {
  match value {
    Some(@moonplist.Text(s)) => Some(s)
    _ => None
  }
}

///|
fn plist_summary(data : Bytes) -> PlistSummary? raise @moonplist.PlistError {
  let value = @moonplist.decode(data)
  match value {
    @moonplist.Dict(entries) => {
      let keys : Array[String] = []
      for entry in entries {
        keys.push(entry.0)
      }
      Some({
        keys,
        bundle_id: text_value(value.get("CFBundleIdentifier")),
        version: text_value(value.get("CFBundleShortVersionString")),
      })
    }
    _ => None
  }
}

///|
/// Profile a Mach-O image and an optional plist. The function is total:
/// malformed or missing inputs become explicit notes instead of panics.
pub fn bundle_profile(
  macho_bytes : Bytes,
  plist_bytes : Bytes?,
) -> BundleReport {
  let macho_format = match @macho.parse(macho_bytes) {
    Ok(m) => "macho-" + m.class.to_string()
    Err(_) => "none"
  }
  let mut note = if macho_format == "none" {
    "no parseable Mach-O image"
  } else {
    "Mach-O parsed"
  }
  let plist = match plist_bytes {
    None => {
      note = note + "; no Info.plist supplied"
      None
    }
    Some(data) =>
      try {
        match plist_summary(data) {
          Some(summary) => {
            note = note + "; Info.plist parsed"
            Some(summary)
          }
          None => {
            note = note + "; Info.plist root is not a dictionary"
            None
          }
        }
      } catch {
        _ => {
          note = note + "; Info.plist rejected"
          None
        }
      }
  }
  { macho_format, plist, note, }
}

///|
fn json_string(s : String) -> String {
  let out : Array[Char] = ['"']
  for c in s {
    let v = c.to_int()
    if v == 34 {
      out.push('\\')
      out.push('"')
    } else if v == 92 {
      out.push('\\')
      out.push('\\')
    } else if v < 0x20 {
      out.push(' ')
    } else {
      out.push(c)
    }
  }
  out.push('"')
  String::from_array(out)
}

///|
fn option_string(value : String?) -> String {
  match value {
    Some(s) => json_string(s)
    None => "null"
  }
}

///|
/// Canonical JSON for CLI and browser consumers.
pub fn BundleReport::to_json(self : BundleReport) -> String {
  let plist = match self.plist {
    None => "null"
    Some(p) => {
      let keys : Array[String] = []
      for key in p.keys {
        keys.push(json_string(key))
      }
      "{\"keys\":[" +
      keys.join(",") +
      "],\"bundle_id\":" +
      option_string(p.bundle_id) +
      ",\"version\":" +
      option_string(p.version) +
      "}"
    }
  }
  "{\"macho_format\":" +
  json_string(self.macho_format) +
  ",\"plist\":" +
  plist +
  ",\"note\":" +
  json_string(self.note) +
  "}"
}
