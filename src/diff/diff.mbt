// diff: normalized facts, deterministic set/map diff, JSON and SARIF output.

///|
priv suberror DiffParseError {
  DiffParseError(String)
}

///|
/// Byte-level location carried by both sides of a diff.
pub(all) struct FactLocation {
  section : String
  rva : Int64
  va : Int64
  file_offset : Int64
  size : Int64
} derive(Eq, Debug)

///|
/// One normalized fact. `key` is stable within `kind`.
pub(all) struct CanonicalFact {
  kind : String
  key : String
  value : String
  location : FactLocation
} derive(Eq, Debug)

///|
/// A complete normalized artifact view.
pub(all) struct FactSet {
  artifact_hash : String
  facts : Array[CanonicalFact]
} derive(Debug)

///|
/// One added, removed, or changed fact.
pub(all) struct DiffItem {
  change : String
  kind : String
  key : String
  old_value : String
  new_value : String
  old_location : FactLocation?
  new_location : FactLocation?
} derive(Debug)

///|
/// Complete deterministic diff.
pub(all) struct DiffReport {
  added : Array[DiffItem]
  removed : Array[DiffItem]
  changed : Array[DiffItem]
} derive(Debug)

///|
fn sort_key(fact : CanonicalFact) -> String {
  fact.kind + "\u{1f}" + fact.key
}

///|
/// Return a sorted copy; input order never affects diff output.
pub fn normalize(facts : Array[CanonicalFact]) -> Array[CanonicalFact] {
  let out = facts.copy()
  out.sort_by(fn(a, b) { sort_key(a).compare(sort_key(b)) })
  out
}

///|
fn location_changed(a : FactLocation, b : FactLocation) -> Bool {
  a != b
}

///|
/// Three-way merge over normalized fact arrays.
pub fn diff(old : FactSet, new : FactSet) -> DiffReport {
  let left = normalize(old.facts)
  let right = normalize(new.facts)
  let added : Array[DiffItem] = []
  let removed : Array[DiffItem] = []
  let changed : Array[DiffItem] = []
  let mut i = 0
  let mut j = 0
  while i < left.length() || j < right.length() {
    if i >= left.length() {
      let f = right[j]
      added.push({
        change: "added",
        kind: f.kind,
        key: f.key,
        old_value: "",
        new_value: f.value,
        old_location: None,
        new_location: Some(f.location),
      })
      j = j + 1
      continue
    }
    if j >= right.length() {
      let f = left[i]
      removed.push({
        change: "removed",
        kind: f.kind,
        key: f.key,
        old_value: f.value,
        new_value: "",
        old_location: Some(f.location),
        new_location: None,
      })
      i = i + 1
      continue
    }
    let a = left[i]
    let b = right[j]
    let cmp = sort_key(a).compare(sort_key(b))
    if cmp < 0 {
      removed.push({
        change: "removed",
        kind: a.kind,
        key: a.key,
        old_value: a.value,
        new_value: "",
        old_location: Some(a.location),
        new_location: None,
      })
      i = i + 1
    } else if cmp > 0 {
      added.push({
        change: "added",
        kind: b.kind,
        key: b.key,
        old_value: "",
        new_value: b.value,
        old_location: None,
        new_location: Some(b.location),
      })
      j = j + 1
    } else if a.value != b.value || location_changed(a.location, b.location) {
      changed.push({
        change: "changed",
        kind: a.kind,
        key: a.key,
        old_value: a.value,
        new_value: b.value,
        old_location: Some(a.location),
        new_location: Some(b.location),
      })
      i = i + 1
      j = j + 1
    } else {
      i = i + 1
      j = j + 1
    }
  }
  { added, removed, changed, }
}

///|
fn jloc(loc : FactLocation) -> Json {
  Json::object({
    "section": Json::string(loc.section),
    "rva": Json::number(loc.rva.to_double()),
    "va": Json::number(loc.va.to_double()),
    "file_offset": Json::number(loc.file_offset.to_double()),
    "size": Json::number(loc.size.to_double()),
  })
}

///|
fn jlocopt(loc : FactLocation?) -> Json {
  match loc {
    Some(value) => jloc(value)
    None => Json::null()
  }
}

///|
fn jitem(item : DiffItem) -> Json {
  Json::object({
    "change": Json::string(item.change),
    "kind": Json::string(item.kind),
    "key": Json::string(item.key),
    "old_value": Json::string(item.old_value),
    "new_value": Json::string(item.new_value),
    "old_location": jlocopt(item.old_location),
    "new_location": jlocopt(item.new_location),
  })
}

///|
/// Canonical JSON diff.
pub fn DiffReport::to_json(self : DiffReport) -> String {
  let added : Array[Json] = []
  for item in self.added {
    added.push(jitem(item))
  }
  let removed : Array[Json] = []
  for item in self.removed {
    removed.push(jitem(item))
  }
  let changed : Array[Json] = []
  for item in self.changed {
    changed.push(jitem(item))
  }
  Json::object({
    "added": Json::array(added),
    "removed": Json::array(removed),
    "changed": Json::array(changed),
  }).stringify()
}

///|
fn sarif_rule(id : String, name : String, description : String) -> Json {
  Json::object({
    "id": Json::string(id),
    "name": Json::string(name),
    "shortDescription": Json::object({ "text": Json::string(description) }),
  })
}

///|
fn sarif_location(loc : FactLocation) -> Json {
  Json::object({
    "physicalLocation": Json::object({
      "artifactLocation": Json::object({ "uri": Json::string("artifact") }),
      "region": Json::object({
        "byteOffset": Json::number(loc.file_offset.to_double()),
        "byteLength": Json::number(loc.size.to_double()),
      }),
    }),
  })
}

///|
fn sarif_item(item : DiffItem) -> Json {
  let loc = match item.new_location {
    Some(value) => Some(value)
    None => item.old_location
  }
  let locations : Array[Json] = []
  match loc {
    Some(value) => locations.push(sarif_location(value))
    None => ()
  }
  let level = if item.change == "added" { "warning" } else { "note" }
  Json::object({
    "ruleId": Json::string("diff-" + item.change),
    "level": Json::string(level),
    "message": Json::object({
      "text": Json::string(item.change + " " + item.kind + " " + item.key),
    }),
    "locations": Json::array(locations),
    "properties": Json::object({
      "change": Json::string(item.change),
      "kind": Json::string(item.kind),
      "key": Json::string(item.key),
      "old_value": Json::string(item.old_value),
      "new_value": Json::string(item.new_value),
    }),
  })
}

///|
/// SARIF 2.1.0 for CI consumption.
pub fn DiffReport::to_sarif(self : DiffReport) -> String {
  let results : Array[Json] = []
  for item in self.added {
    results.push(sarif_item(item))
  }
  for item in self.removed {
    results.push(sarif_item(item))
  }
  for item in self.changed {
    results.push(sarif_item(item))
  }
  Json::object({
    "version": Json::string("2.1.0"),
    "$schema": Json::string("https://json.schemastore.org/sarif-2.1.0.json"),
    "runs": Json::array([
      Json::object({
        "tool": Json::object({
          "driver": Json::object({
            "name": Json::string("MoonForge RE Workbench"),
            "version": Json::string("0.2.0"),
            "informationUri": Json::string(
              "https://github.com/NaIWaniubi/moonforge",
            ),
            "rules": Json::array([
              sarif_rule(
                "diff-added", "DiffAdded", "A normalized fact was added.",
              ),
              sarif_rule(
                "diff-removed", "DiffRemoved", "A normalized fact was removed.",
              ),
              sarif_rule(
                "diff-changed", "DiffChanged", "A normalized fact changed.",
              ),
            ]),
          }),
        }),
        "results": Json::array(results),
      }),
    ]),
  }).stringify()
}

///|
fn parse_location(value : Json) -> FactLocation raise DiffParseError {
  match value {
    Object(obj) => {
      let section = match obj.get("section") {
        Some(String(s)) => s
        _ => raise DiffParseError("location.section must be a string")
      }
      let rva = match obj.get("rva") {
        Some(Number(n, ..)) => n.to_int64()
        _ => raise DiffParseError("location.rva must be a number")
      }
      let va = match obj.get("va") {
        Some(Number(n, ..)) => n.to_int64()
        _ => raise DiffParseError("location.va must be a number")
      }
      let file_offset = match obj.get("file_offset") {
        Some(Number(n, ..)) => n.to_int64()
        _ => raise DiffParseError("location.file_offset must be a number")
      }
      let size = match obj.get("size") {
        Some(Number(n, ..)) => n.to_int64()
        _ => raise DiffParseError("location.size must be a number")
      }
      { section, rva, va, file_offset, size, }
    }
    _ => raise DiffParseError("location must be an object")
  }
}

///|
fn parse_fact(value : Json) -> CanonicalFact raise DiffParseError {
  match value {
    Object(obj) => {
      let kind = match obj.get("kind") {
        Some(String(s)) if s.length() > 0 => s
        _ => raise DiffParseError("fact.kind must be a non-empty string")
      }
      let key = match obj.get("key") {
        Some(String(s)) if s.length() > 0 => s
        _ => raise DiffParseError("fact.key must be a non-empty string")
      }
      let val = match obj.get("value") {
        Some(String(s)) => s
        _ => raise DiffParseError("fact.value must be a string")
      }
      let location = match obj.get("location") {
        Some(loc) =>
          parse_location(loc) catch {
            DiffParseError(message) => raise DiffParseError(message)
          }
        None => raise DiffParseError("fact.location is required")
      }
      { kind, key, value: val, location, }
    }
    _ => raise DiffParseError("fact must be an object")
  }
}

///|
/// Parse the canonical fact-set JSON produced by MoonForge adapters.
pub fn FactSet::from_json(text : String) -> Result[FactSet, String] {
  let root = @json.parse(text, reject_duplicate_keys=true) catch {
    _ => return Err("invalid fact-set JSON")
  }
  match root {
    Object(obj) => {
      let artifact_hash = match obj.get("artifact_hash") {
        Some(String(s)) => s
        _ => return Err("artifact_hash must be a string")
      }
      let facts_json = match obj.get("facts") {
        Some(Array(items)) => items
        _ => return Err("facts must be an array")
      }
      let facts : Array[CanonicalFact] = []
      for item in facts_json {
        let fact = parse_fact(item) catch {
          DiffParseError(message) => return Err(message)
        }
        facts.push(fact)
      }
      Ok({ artifact_hash, facts: normalize(facts), })
    }
    _ => Err("fact-set root must be an object")
  }
}
