// web: wasm entry for the browser workbench.
//
// Legacy protocol: argv = ["moonforge-web", "input.bin", query?]
// v2 protocol:     argv = ["moonforge-web-v2", file1, file2, ..., "--query", term]
//
// The host supplies a per-run virtual filesystem. Everything printed to stdout
// is one JSON value; the page and Node acceptance test share this exact code.

///|
fn read_bytes(path : String) -> Bytes {
  @fs.read_file_to_bytes(path) catch {
    _ => Bytes::from_array([])
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
fn facts_for(name : String, data : Bytes) -> @diff.FactSet {
  let record = @core.record_of_bytes(name, data)
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
  if record.format == @core.Pe {
    let xref = @peinfo.xref_v2_of(data)
    for pair in xref.by_api {
      facts.push({
        kind: "xref",
        key: pair.0,
        value: pair.1.to_string(),
        location: no_loc(),
      })
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
fn artifact_json(name : String, data : Bytes) -> Json {
  let record = @core.record_of_bytes(name, data)
  let digest = match record.sha256 {
    Some(value) => value
    None => ""
  }
  let xref = if record.format == @core.Pe {
    parse_json_or_null(@peinfo.xref_v2_of(data).to_json())
  } else {
    Json::null()
  }
  let wasm = if data.has_prefix(b"\x00asm"[:]) {
    match @wasmcheck.wasm_report(data) {
      Ok(sections) => parse_json_or_null(@wasmcheck.sections_to_json(sections))
      Err(_) => Json::null()
    }
  } else {
    Json::null()
  }
  let evidence = @evidence.artifact(
    name,
    data,
    record.format.label(),
    if data.length() == 0 {
      "empty"
    } else {
      "parsed"
    },
  )
  Json::object({
    "name": Json::string(name),
    "format": Json::string(record.format.label()),
    "size": Json::number(record.size.to_double()),
    "sha256": Json::string(digest),
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
  let mut query = ""
  let mut i = 1
  while i < argv.length() {
    if argv[i] == "--query" && i + 1 < argv.length() {
      query = argv[i + 1]
      i = i + 2
    } else {
      names.push(argv[i])
      datas.push(read_bytes(argv[i]))
      i = i + 1
    }
  }
  let artifacts : Array[Json] = []
  for j = 0; j < names.length(); j = j + 1 {
    artifacts.push(artifact_json(names[j], datas[j]))
  }
  let diff = if names.length() >= 2 {
    parse_json_or_null(
      @diff.diff(facts_for(names[0], datas[0]), facts_for(names[1], datas[1])).to_json(),
    )
  } else {
    Json::null()
  }
  let bundle = if names.length() >= 2 {
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
  let notes : Array[Json] = [
    Json::string("v2 multi-artifact protocol"),
    Json::string("diff compares normalized artifact/summary/xref facts"),
    Json::string("bundle profiling pairs a Mach-O with an Info.plist"),
  ]
  Json::object({
    "protocol": Json::string("moonforge-v2"),
    "artifacts": Json::array(artifacts),
    "diff": diff,
    "bundle": bundle,
    "matches": matches,
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
