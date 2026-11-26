// xref: resolve imported-API call sites.
//
// The question this answers: "this binary imports VirtualAlloc — where is it
// actually called?" Neither the parser (which knows the import name) nor the
// disassembler (which sees `call 0x14000babc`) can answer alone. Joining them
// is this package's whole job.
//
// Trust boundary, stated once and enforced below:
//   - Only statically-encoded calls participate: `call rel32` (E8). An
//     indirect `call rax` / `call [mem]` has no static target and is not
//     guessed — it is counted and reported separately.
//   - A call site is attributed to an import only when its target lands
//     exactly on that import's IAT slot RVA. Nothing is matched by name
//     similarity, ordinal heuristics, or proximity.
//   - Anything unmatched is reported as an unresolved target, never dropped.

///|
/// One resolved call site: `api` was reached by the call at `call_addr`.
pub(all) struct ApiCallSite {
  api : String
  /// Address of the `call` instruction itself.
  call_addr : Int64
  /// Address the call transfers to (the IAT slot RVA, rebased).
  target_addr : Int64
} derive(Eq, Debug)

///|
/// The full cross-reference result for one binary.
pub(all) struct XrefTable {
  /// Per-API call counts, sorted by API name for stable output.
  by_api : Array[(String, Int)]
  /// Every resolved call site, in ascending call address order.
  sites : Array[ApiCallSite]
  /// Direct call targets that matched no import slot (resolved intra-binary
  /// calls, plus imports whose slot we could not name). Never discarded.
  unresolved : Int
  /// Indirect calls seen. They have no static target, so they cannot be
  /// attributed; the count is reported so the reader knows what is missing.
  indirect_calls : Int
} derive(Debug)

///|
/// A `call rel32` observation from the disassembly: the instruction address and
/// the absolute target it transfers to.
struct CallEdge {
  call_addr : Int64
  target : Int64
} derive(Debug)

///|
/// Index of the import whose slot RVA equals `rva`, or -1.
fn slot_index(slots : Array[(Int64, String)], rva : Int64) -> Int {
  let mut lo = 0
  let mut hi = slots.length() - 1
  while lo <= hi {
    let mid = (lo + hi) / 2
    let a = slots[mid].0
    if a == rva {
      return mid
    } else if a < rva {
      lo = mid + 1
    } else {
      hi = mid - 1
    }
  }
  -1
}

///|
/// Build the table from a PE's import slots and its `.text` bytes.
///
/// `slots` are `(slot_rva, api_label)` pairs — the caller builds them from the
/// PE import table and the IAT, sorted by `slot_rva` ascending. `code_base` is
/// the virtual address the first byte of `code` is loaded at.
pub fn build_xref(
  slots : Array[(Int64, String)],
  code : Bytes,
  code_base : Int64,
) -> XrefTable {
  // One instruction per byte is the hard upper bound (the shortest x86-64
  // encoding is a single byte), so nothing in the buffer can be cut off. An
  // earlier `length/2` guess silently dropped the tail of a long .text — that
  // is exactly the kind of quiet truncation this tool refuses to ship.
  let insns = @disasm.disassemble(code, code_base, code.length() + 1)
  let sites : Array[ApiCallSite] = []
  let mut unresolved = 0
  let mut indirect = 0
  for ins in insns {
    if ins.mnemonic != "call" {
      continue
    }
    let insn_end = ins.addr + ins.len.to_int64()
    match call_target(ins.op_str, insn_end) {
      Some(target) => {
        let i = slot_index(slots, target)
        if i >= 0 {
          sites.push({ api: slots[i].1, call_addr: ins.addr, target_addr: target })
        } else {
          unresolved = unresolved + 1
        }
      }
      None => {
        // `call rax`, `call qword ptr [...]` — no static target.
        indirect = indirect + 1
      }
    }
  }
  // Counts per API, sorted by name so two runs produce identical output.
  let counts : Array[(String, Int)] = []
  for site in sites {
    let mut found = false
    for i = 0; i < counts.length(); i = i + 1 {
      if counts[i].0 == site.api {
        counts[i] = (counts[i].0, counts[i].1 + 1)
        found = true
        break
      }
    }
    if !(found) {
      counts.push((site.api, 1))
    }
  }
  counts.sort_by(fn(a, b) { a.0.compare(b.0) })
  { by_api: counts, sites, unresolved, indirect_calls: indirect }
}

///|
/// Read a call's static transfer target out of the operand text the
/// disassembler produced. Two shapes carry a static address:
///
///   `0x140001234`                — direct `call rel32`
///   `qword ptr [rip+0x29175]`    — import thunk; the operand names an IAT slot
///
/// For the rip-relative form the absolute address is `insn_end + disp`, because
/// x86-64 `rip` is already past the instruction at execution time. Everything
/// else — registers, non-rip memory operands — yields None and is counted as
/// indirect rather than guessed.
pub fn call_target(op_str : String, insn_end : Int64) -> Int64? {
  let text = op_str.to_string()
  if text.has_prefix("0x") {
    return parse_hex(text, 2)
  }
  let open = index_of(text, 91)
  if open < 0 {
    return None
  }
  let close = index_of_from(text, 93, open)
  if close < 0 {
    return None
  }
  let inner = text[open + 1:close].to_owned()
  if !(inner.has_prefix("rip")) {
    return None
  }
  let rest = inner[3:inner.length()].to_owned()
  let mut sign : Int64 = 1L
  let mut at = 0
  if rest.length() > 0 && rest[0].to_int() == 43 {
    at = 1
  } else if rest.length() > 0 && rest[0].to_int() == 45 {
    sign = -1L
    at = 1
  } else if rest.length() > 0 {
    return None
  }
  if rest.length() == at {
    // A bare `[rip]` is never emitted by this encoder; refuse rather than
    // assume a zero displacement.
    return None
  }
  let disp_text = rest[at:rest.length()].to_owned()
  let disp = match parse_hex(disp_text, 0) {
    Some(v) => v
    None => return None
  }
  Some(insn_end + sign * disp)
}

///|
fn index_of(s : String, ch : Int) -> Int {
  index_of_from(s, ch, 0)
}

///|
fn index_of_from(s : String, ch : Int, from : Int) -> Int {
  let mut i = from
  while i < s.length() {
    if s[i].to_int() == ch {
      return i
    }
    i = i + 1
  }
  -1
}

///|
/// Hex digits, with an optional `0x` prefix. `skip` is where the digits start.
pub fn parse_hex(text : String, skip : Int) -> Int64? {
  let mut value : Int64 = 0L
  let mut any = false
  let mut i = skip
  if i + 1 < text.length() &&
    text[i].to_int() == 48 &&
    (text[i + 1].to_int() == 120 || text[i + 1].to_int() == 88) {
    i = i + 2
  }
  while i < text.length() {
    let v = hex_digit(text[i].to_int())
    match v {
      Some(d) => {
        value = value * 16L + d.to_int64()
        any = true
      }
      None => return None
    }
    i = i + 1
  }
  if any {
    Some(value)
  } else {
    None
  }
}

///|
fn hex_digit(v : Int) -> Int? {
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
pub fn XrefTable::to_json(self : XrefTable) -> String {
  let counts : Array[String] = []
  for pair in self.by_api {
    counts.push(
      "{\"api\":\"" + escape(pair.0) + "\",\"count\":" + pair.1.to_string() + "}",
    )
  }
  let sites : Array[String] = []
  for s in self.sites {
    sites.push(
      "{\"api\":\"" +
      escape(s.api) +
      "\",\"call\":" +
      s.call_addr.to_string() +
      ",\"target\":" +
      s.target_addr.to_string() +
      "}",
    )
  }
  "{\"by_api\":[" +
  counts.join(",") +
  "],\"sites\":[" +
  sites.join(",") +
  "],\"unresolved\":" +
  self.unresolved.to_string() +
  ",\"indirect_calls\":" +
  self.indirect_calls.to_string() +
  "}"
}

///|
fn escape(s : String) -> String {
  let out : Array[Char] = []
  for c in s {
    let v = c.to_int()
    if v == 34 {
      out.push('\\')
      out.push('"')
    } else if v == 92 {
      out.push('\\')
      out.push('\\')
    } else {
      out.push(c)
    }
  }
  String::from_array(out)
}

// ─── xref v2: section-aware, byte-derived call evidence ──────────────────────

///| One executable section supplied by the format adapter.
pub(all) struct XrefSection {
  name : String
  base : Int64
  code : Bytes
} derive(Debug)

///| One attributed call site with enough provenance to audit the decision.
pub(all) struct XrefSiteV2 {
  api : String
  call_addr : Int64
  target_addr : Int64
  section : String
  rva : Int64
  instruction_bytes : Array[Int]
  rule : String
} derive(Debug)

///| Complete call ledger. The core invariant is:
/// `decoded_calls = sites.length + unresolved_direct + indirect_calls`.
pub(all) struct XrefReportV2 {
  sites : Array[XrefSiteV2]
  by_api : Array[(String, Int)]
  decoded_calls : Int
  refused_bytes : Int
  direct_calls : Int
  indirect_calls : Int
  unresolved_direct : Int
  sections_scanned : Int
} derive(Debug)

fn byte_ints(data : Bytes) -> Array[Int] {
  let out : Array[Int] = []
  for b in data {
    out.push(b.to_int())
  }
  out
}

fn disp32(data : Bytes, at : Int) -> Int64 {
  let value = data[at].to_int() |
    (data[at + 1].to_int() << 8) |
    (data[at + 2].to_int() << 16) |
    (data[at + 3].to_int() << 24)
  if (value & 0x80000000) != 0 {
    value.to_int64() - 0x100000000L
  } else {
    value.to_int64()
  }
}

///| Derive a static call target from the encoded instruction bytes, not from
/// the disassembler's display string. Only E8 rel32 and FF 15 rip-rel32 are
/// accepted; every other call shape stays indirect.
fn call_target_bytes(data : Bytes, addr : Int64, len : Int) -> (Int64, String)? {
  if len >= 5 && data[0].to_int() == 0xE8 {
    Some((addr + 5L + disp32(data, 1), "E8-rel32"))
  } else if len >= 6 && data[0].to_int() == 0xFF && data[1].to_int() == 0x15 {
    Some((addr + 6L + disp32(data, 2), "FF15-rip-rel32"))
  } else {
    None
  }
}

///| Section-aware xref. Each section is decoded independently so a multi-text
/// image never concatenates addresses from different bases.
pub fn build_xref_v2(
  sections : Array[XrefSection],
  slots : Array[(Int64, String)],
) -> XrefReportV2 {
  let sites : Array[XrefSiteV2] = []
  let mut decoded_calls = 0
  let mut refused_bytes = 0
  let mut direct_calls = 0
  let mut indirect_calls = 0
  let mut unresolved_direct = 0
  for section in sections {
    let insns = @disasm.disassemble(section.code, section.base, section.code.length() + 1)
    for ins in insns {
      if ins.mnemonic == ".byte" {
        refused_bytes = refused_bytes + ins.len
        continue
      }
      if ins.mnemonic != "call" {
        continue
      }
      decoded_calls = decoded_calls + 1
      match call_target_bytes(ins.bytes, ins.addr, ins.len) {
        Some((target, rule)) => {
          direct_calls = direct_calls + 1
          let i = slot_index(slots, target)
          if i >= 0 {
            sites.push({
              api: slots[i].1,
              call_addr: ins.addr,
              target_addr: target,
              section: section.name,
              rva: ins.addr - section.base,
              instruction_bytes: byte_ints(ins.bytes),
              rule,
            })
          } else {
            unresolved_direct = unresolved_direct + 1
          }
        }
        None => indirect_calls = indirect_calls + 1
      }
    }
  }
  let counts : Array[(String, Int)] = []
  for site in sites {
    let mut found = false
    for i = 0; i < counts.length(); i = i + 1 {
      if counts[i].0 == site.api {
        counts[i] = (counts[i].0, counts[i].1 + 1)
        found = true
        break
      }
    }
    if !(found) {
      counts.push((site.api, 1))
    }
  }
  counts.sort_by(fn(a, b) { a.0.compare(b.0) })
  {
    sites,
    by_api: counts,
    decoded_calls,
    refused_bytes,
    direct_calls,
    indirect_calls,
    unresolved_direct,
    sections_scanned: sections.length(),
  }
}

fn json_array_ints(values : Array[Int]) -> String {
  let parts : Array[String] = []
  for value in values {
    parts.push(value.to_string())
  }
  "[" + parts.join(",") + "]"
}

///| Canonical JSON for the v2 ledger.
pub fn XrefReportV2::to_json(self : XrefReportV2) -> String {
  let counts : Array[String] = []
  for pair in self.by_api {
    counts.push("{\"api\":\"" + escape(pair.0) + "\",\"count\":" + pair.1.to_string() + "}")
  }
  let sites : Array[String] = []
  for site in self.sites {
    sites.push(
      "{\"api\":\"" +
      escape(site.api) +
      "\",\"call\":" +
      site.call_addr.to_string() +
      ",\"target\":" +
      site.target_addr.to_string() +
      ",\"section\":\"" +
      escape(site.section) +
      "\",\"rva\":" +
      site.rva.to_string() +
      ",\"bytes\":" +
      json_array_ints(site.instruction_bytes) +
      ",\"rule\":\"" +
      escape(site.rule) +
      "\"}",
    )
  }
  "{\"by_api\":[" +
  counts.join(",") +
  "],\"sites\":[" +
  sites.join(",") +
  "],\"ledger\":{\"decoded_calls\":" +
  self.decoded_calls.to_string() +
  ",\"refused_bytes\":" +
  self.refused_bytes.to_string() +
  ",\"direct_calls\":" +
  self.direct_calls.to_string() +
  ",\"indirect_calls\":" +
  self.indirect_calls.to_string() +
  ",\"unresolved_direct\":" +
  self.unresolved_direct.to_string() +
  ",\"sections_scanned\":" +
  self.sections_scanned.to_string() +
  "}}"
}
