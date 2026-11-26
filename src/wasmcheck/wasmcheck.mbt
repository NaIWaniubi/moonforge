// wasmcheck: one bounded, deterministic section report per WASM artifact.

///|
/// One section in input order.
pub struct WasmSection {
  name : String
  offset : Int32
  size : Int32
} derive(Debug)

///|
fn ints(data : Bytes) -> Array[Int32] {
  let out : Array[Int32] = []
  for b in data {
    out.push(b.to_int())
  }
  out
}

///|
/// Parse a WASM module and return its sections. The parser validates magic,
/// version, section ordering, and declared payload bounds.
pub fn wasm_report(data : Bytes) -> Result[Array[WasmSection], String] {
  match @wasm_inspect.parse_module(ints(data)) {
    Ok(parsed) => {
      let out : Array[WasmSection] = []
      for section in parsed.sections() {
        let name = match section.custom_name {
          Some(value) => "custom:" + value
          None => section.kind.label()
        }
        out.push({
          name,
          offset: section.full.start,
          size: section.full.size(),
        })
      }
      Ok(out)
    }
    Err(error) => Err(error.message())
  }
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
/// Canonical JSON array of sections.
pub fn sections_to_json(sections : Array[WasmSection]) -> String {
  let parts : Array[String] = []
  for section in sections {
    parts.push(
      "{\"name\":" +
      json_string(section.name) +
      ",\"offset\":" +
      section.offset.to_string() +
      ",\"size\":" +
      section.size.to_string() +
      "}",
    )
  }
  "[" + parts.join(",") + "]"
}
