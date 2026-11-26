// web: wasm entry for the browser workbench.
//
// Legacy protocol: argv = ["moonforge-web", "input.bin", query?]
// v2 protocol:     argv = ["moonforge-web-v2", file1, file2, ..., "--query", term,
//                          "--policy", policyJson]
//
// The host supplies a per-run virtual filesystem. Everything printed to stdout
// is one JSON value; the page and Node acceptance test share this exact code.

///|
fn read_bytes(path : String) -> Bytes? {
  Some(@fs.read_file_to_bytes(path)) catch {
    _ => None
  }
}

///|
fn parse_json_or_null(text : String) -> Json {
  @json.parse(text) catch {
    _ => Json::null()
  }
}

///|
fn no_loc() -> @diff.FactLocation {
  { section: "", rva: 0L, va: 0L, file_offset: 0L, size: 0L, }
}

///|
fn is_plist(data : Bytes) -> Bool {
  data.has_prefix(b"bplist00"[:]) ||
  data.has_prefix(b"<?xml"[:]) ||
  data.has_prefix(b"<plist"[:])
}

///|
fn ints(data : Bytes) -> Array[Int32] {
  let out : Array[Int32] = []
  for b in data {
    out.push(b.to_int())
  }
  out
}

///|
fn add_fact(
  facts : Array[@diff.CanonicalFact],
  kind : String,
  key : String,
  value : String,
  location : @diff.FactLocation,
) -> Unit {
  facts.push({ kind, key, value, location, })
}

///|
fn plist_text(value : @moonplist.Value) -> String {
  match value {
    @moonplist.Text(s) => s
    @moonplist.Integer(n) => n.to_string()
    @moonplist.Unsigned(n) => n.to_string()
    @moonplist.Real(n) => n.to_string()
    @moonplist.Boolean(b) => b.to_string()
    _ => value.kind()
  }
}

///|
fn facts_for(name : String, data : Bytes, read_ok : Bool) -> @diff.FactSet {
  let record = @core.record_of_bytes(name, data)
  let status = if read_ok { record.parse_status } else { "missing" }
  let facts : Array[@diff.CanonicalFact] = [
    {
      kind: "artifact",
      key: "format",
      value: record.format.label(),
      location: no_loc(),
    },
    {
      kind: "artifact",
      key: "size",
      value: record.size.to_string(),
      location: no_loc(),
    },
    {
      kind: "artifact",
      key: "parse_status",
      value: status,
      location: no_loc(),
    },
    {
      kind: "summary",
      key: "sections",
      value: record.summary.sections.to_string(),
      location: no_loc(),
    },
    {
      kind: "summary",
      key: "symbols",
      value: record.summary.symbols.to_string(),
      location: no_loc(),
    },
    {
      kind: "summary",
      key: "imports",
      value: record.summary.imports.to_string(),
      location: no_loc(),
    },
    {
      kind: "summary",
      key: "exports",
      value: record.summary.exports.to_string(),
      location: no_loc(),
    },
  ]
  if status != "parsed" {
    return {
      artifact_hash: match record.sha256 {
        Some(value) => value
        None => ""
      },
      facts,
    }
  }
  match record.format {
    @core.Pe =>
      match @pe.parse(data) {
        Ok(pe) => {
          for sec in pe.sections {
            add_fact(
              facts,
              "section",
              sec.name,
              sec.flags + ":" + sec.size.to_string(),
              {
                section: sec.name,
                rva: sec.vaddr,
                va: sec.vaddr,
                file_offset: sec.offset,
                size: sec.size,
              },
            )
          }
          for imp in pe.imports {
            add_fact(
              facts,
              "import",
              imp.library + "!" + imp.name,
              imp.name,
              no_loc(),
            )
          }
          for exp in pe.exports {
            add_fact(facts, "export", exp.name, exp.rva.to_string(), no_loc())
          }
          for sym in pe.symbols {
            add_fact(
              facts,
              "symbol",
              sym.name,
              sym.kind + ":" + sym.bind,
              no_loc(),
            )
          }
        }
        Err(_) => ()
      }
    @core.Elf =>
      match @elf.parse(data) {
        Ok(elf) => {
          for sec in elf.sections {
            add_fact(
              facts,
              "section",
              sec.name,
              sec.flags + ":" + sec.size.to_string(),
              {
                section: sec.name,
                rva: sec.vaddr,
                va: sec.vaddr,
                file_offset: sec.offset,
                size: sec.size,
              },
            )
          }
          for imp in elf.imports {
            add_fact(
              facts,
              "import",
              imp.library + "!" + imp.name,
              imp.name,
              no_loc(),
            )
          }
          for exp in elf.exports {
            add_fact(facts, "export", exp.name, exp.rva.to_string(), no_loc())
          }
          for sym in elf.symbols {
            add_fact(
              facts,
              "symbol",
              sym.name,
              sym.kind + ":" + sym.bind,
              no_loc(),
            )
          }
        }
        Err(_) => ()
      }
    @core.MachO =>
      match @macho.parse(data) {
        Ok(m) => {
          for sec in m.sections {
            add_fact(
              facts,
              "section",
              sec.name,
              sec.flags + ":" + sec.size.to_string(),
              {
                section: sec.name,
                rva: sec.vaddr,
                va: sec.vaddr,
                file_offset: sec.offset,
                size: sec.size,
              },
            )
          }
          for imp in m.imports {
            add_fact(
              facts,
              "import",
              imp.library + "!" + imp.name,
              imp.name,
              no_loc(),
            )
          }
          for exp in m.exports {
            add_fact(facts, "export", exp.name, exp.rva.to_string(), no_loc())
          }
          for sym in m.symbols {
            add_fact(
              facts,
              "symbol",
              sym.name,
              sym.kind + ":" + sym.bind,
              no_loc(),
            )
          }
        }
        Err(_) => ()
      }
    @core.Wasm => ()
    @core.Plist => {
      let value = @moonplist.decode(data) catch { _ => @moonplist.Null }
      match value {
        @moonplist.Dict(entries) =>
          for entry in entries {
            add_fact(facts, "plist", entry.0, plist_text(entry.1), no_loc())
          }
        _ => ()
      }
    }
    @core.Unknown => ()
  }
  if data.has_prefix(b"\x00asm"[:]) {
    match @wasm_inspect.parse_module(ints(data)) {
      Ok(parsed) => {
        for section in parsed.sections() {
          let label = match section.custom_name {
            Some(value) => "custom:" + value
            None => section.kind.label()
          }
          add_fact(
            facts,
            "wasm_section",
            label,
            section.payload_size().to_string(),
            {
              section: label,
              rva: 0L,
              va: 0L,
              file_offset: section.full.start.to_int64(),
              size: section.full.size().to_int64(),
            },
          )
        }
        match @wasm_inspect.decode_module(parsed) {
          Ok(decoded) => {
            for imp in decoded.imports() {
              add_fact(
                facts,
                "wasm_import",
                imp.module_name + "!" + imp.name,
                imp.kind.label(),
                no_loc(),
              )
            }
            for exp in decoded.exports() {
              add_fact(
                facts,
                "wasm_export",
                exp.name,
                exp.kind.label(),
                no_loc(),
              )
            }
          }
          Err(_) => ()
        }
      }
      Err(_) => ()
    }
  }
  {
    artifact_hash: match record.sha256 {
      Some(value) => value
      None => ""
    },
    facts,
  }
}

///|
fn artifact_json(name : String, data : Bytes, read_ok : Bool) -> Json {
  let record = @core.record_of_bytes(name, data)
  let status = if read_ok { record.parse_status } else { "missing" }
  let digest = match record.sha256 {
    Some(value) => value
    None => ""
  }
  let xref = if read_ok && status == "parsed" && record.format == @core.Pe {
    parse_json_or_null(@peinfo.xref_v2_of(data).to_json())
  } else {
    Json::null()
  }
  let wasm = if read_ok && status == "parsed" && data.has_prefix(b"\x00asm"[:]) {
    match @wasmcheck.wasm_report(data) {
      Ok(sections) => parse_json_or_null(@wasmcheck.sections_to_json(sections))
      Err(_) => Json::null()
    }
  } else {
    Json::null()
  }
  let evidence = @evidence.artifact(name, data, record.format.label(), status)
  Json::object({
    "name": Json::string(name),
    "format": Json::string(record.format.label()),
    "size": Json::number(record.size.to_double()),
    "sha256": Json::string(digest),
    "read_status": Json::string(if read_ok { "ok" } else { "missing" }),
    "parse_status": Json::string(status),
    "summary": Json::object({
      "sections": Json::number(record.summary.sections.to_double()),
      "symbols": Json::number(record.summary.symbols.to_double()),
      "imports": Json::number(record.summary.imports.to_double()),
      "exports": Json::number(record.summary.exports.to_double()),
    }),
    "xref_v2": xref,
    "wasm": wasm,
    "evidence": Json::object({
      "schema_version": Json::string("1"),
      "artifact": Json::object({
        "path": Json::string(evidence.path),
        "size": Json::number(evidence.size.to_double()),
        "sha256": match evidence.sha256 {
          Some(value) => Json::string(value)
          None => Json::null()
        },
        "format": Json::string(evidence.format),
        "parse_status": Json::string(evidence.parse_status),
      }),
    }),
  })
}

///|
fn run_v2(argv : Array[String]) -> Unit {
  let names : Array[String] = []
  let datas : Array[Bytes] = []
  let read_oks : Array[Bool] = []
  let mut query = ""
  let mut policy_text = ""
  let mut i = 1
  while i < argv.length() {
    if argv[i] == "--query" && i + 1 < argv.length() {
      query = argv[i + 1]
      i = i + 2
    } else if argv[i] == "--policy" && i + 1 < argv.length() {
      policy_text = argv[i + 1]
      i = i + 2
    } else {
      names.push(argv[i])
      let read = read_bytes(argv[i])
      match read {
        Some(data) => {
          datas.push(data)
          read_oks.push(true)
        }
        None => {
          datas.push(Bytes::from_array([]))
          read_oks.push(false)
        }
      }
      i = i + 1
    }
  }
  let artifacts : Array[Json] = []
  for j = 0; j < names.length(); j = j + 1 {
    artifacts.push(artifact_json(names[j], datas[j], read_oks[j]))
  }
  let diff = if names.length() >= 2 {
    parse_json_or_null(
      @diff.diff(
        facts_for(names[0], datas[0], read_oks[0]),
        facts_for(names[1], datas[1], read_oks[1]),
      ).to_json(),
    )
  } else {
    Json::null()
  }
  let bundle = if names.length() >= 2 && read_oks[0] && read_oks[1] {
    if @core.record_of_bytes(names[0], datas[0]).format == @core.MachO &&
      is_plist(datas[1]) {
      parse_json_or_null(
        @bundle.bundle_profile(datas[0], Some(datas[1])).to_json(),
      )
    } else if @core.record_of_bytes(names[1], datas[1]).format == @core.MachO &&
      is_plist(datas[0]) {
      parse_json_or_null(
        @bundle.bundle_profile(datas[1], Some(datas[0])).to_json(),
      )
    } else {
      Json::null()
    }
  } else {
    Json::null()
  }
  let docs : Array[@corpus.CorpusDoc] = []
  for j = 0; j < names.length(); j = j + 1 {
    docs.push({ path: names[j], text: @corpus.strings_of(datas[j], 4), })
  }
  let matches = if query.length() > 0 {
    let idx = @corpus.new_index()
    @corpus.ingest(idx, docs)
    let hits = @corpus.search(idx, query, 50) catch { _ => [] }
    parse_json_or_null(@corpus.results_to_json(hits, docs, query))
  } else {
    Json::array([])
  }
  let gate = if policy_text.length() > 0 && names.length() >= 2 {
    match @policy.parse_policy(policy_text) {
      Ok(policy) => {
        let report = @diff.diff(
          facts_for(names[0], datas[0], read_oks[0]),
          facts_for(names[1], datas[1], read_oks[1]),
        )
        parse_json_or_null(@policy.evaluate(report, policy).to_json())
      }
      Err(error) =>
        Json::object({
          "passed": Json::boolean(false),
          "error": Json::string(error),
          "violations": Json::array([]),
        })
    }
  } else {
    Json::null()
  }
  let notes : Array[Json] = [
    Json::string("v2 multi-artifact protocol"),
    Json::string(
      "diff compares normalized artifact/section/import/export/symbol/plist/wasm facts",
    ),
    Json::string("bundle profiling pairs a Mach-O with an Info.plist"),
    Json::string("policy gate is optional and evaluated in-browser"),
  ]
  Json::object({
    "protocol": Json::string("moonforge-v2"),
    "artifacts": Json::array(artifacts),
    "diff": diff,
    "bundle": bundle,
    "matches": matches,
    "gate": gate,
    "notes": Json::array(notes),
  }).stringify()
  |> println
}

///|
fn main {
  let argv = @env.args()
  if argv.length() > 0 && argv[0] == "moonforge-web-v2" {
    run_v2(argv)
    return
  }
  let path = if argv.length() > 1 { argv[1] } else { "input.bin" }
  let data = @fs.read_file_to_bytes(path) catch {
    _ => {
      println("{\"error\":\"cannot read input\"}")
      return
    }
  }
  let record = @core.record_of_bytes("input.bin", data)
  let digest = match record.sha256 {
    Some(d) => d
    None => ""
  }
  let structure = "\"format\":\"" +
    record.format.label() +
    "\",\"size\":" +
    record.size.to_string() +
    ",\"sha256\":\"" +
    digest +
    "\",\"parse_status\":\"" +
    record.parse_status +
    "\",\"sections\":" +
    record.summary.sections.to_string() +
    ",\"imports\":" +
    record.summary.imports.to_string() +
    ",\"symbols\":" +
    record.summary.symbols.to_string()
  let xref = if record.format == @core.Pe {
    let table = @peinfo.xref_of(data)
    "\"xref\":{\"slots\":" +
    @peinfo.slot_count(data).to_string() +
    ",\"sites\":" +
    table.sites.length().to_string() +
    ",\"apis\":" +
    table.by_api.length().to_string() +
    ",\"unresolved\":" +
    table.unresolved.to_string() +
    ",\"indirect\":" +
    table.indirect_calls.to_string() +
    ",\"top\":" +
    top_apis(table) +
    "}"
  } else {
    "\"xref\":null"
  }
  let text = @corpus.strings_of(data, 4)
  let idx = @corpus.new_index()
  @corpus.ingest(idx, [{ path: "input.bin", text, }])
  let query = if argv.length() > 2 { argv[2] } else { "" }
  let matches = if query.length() > 0 {
    let hits = @corpus.search(idx, query, 20) catch { _ => [] }
    @corpus.results_to_json(hits, [{ path: "input.bin", text, }], query)
  } else {
    "[]"
  }
  println(
    "{" +
    structure +
    "," +
    xref +
    ",\"text_bytes\":" +
    text.length().to_string() +
    ",\"matches\":" +
    matches +
    "}",
  )
}

///|
fn top_apis(table : @xref.XrefTable) -> String {
  let parts : Array[String] = []
  let mut i = 0
  while i < table.by_api.length() && i < 8 {
    let pair = table.by_api[i]
    parts.push(
      "{\"api\":\"" + pair.0 + "\",\"count\":" + pair.1.to_string() + "}",
    )
    i = i + 1
  }
  "[" + parts.join(",") + "]"
}
