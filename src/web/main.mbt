// web: wasm entry for the browser workbench.
//
// The host glue (web/index.html) supplies a virtual filesystem holding one file
// at "input.bin" and calls main with argv. Everything printed to stdout is one
// JSON object, which the glue renders. There is no fs, no network and no DOM
// access in here — the same MoonBit code that backs the CLI does the work.

///|
fn main {
  let argv = @env.args()
  let path = if argv.length() > 1 {
    argv[1]
  } else {
    "input.bin"
  }
  let data = @fs.read_file_to_bytes(path) catch {
    _ => {
      println("{\"error\":\"cannot read input\"}")
      return
    }
  }
  let record = @core.record_of_bytes("input.bin", data)
  // Structure block, shared by every format.
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
  // xref block: only meaningful for PE, and reported as empty otherwise rather
  // than as a fake zero.
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
  // Text preview + search over this one file's strings.
  let text = @corpus.strings_of(data, 4)
  let idx = @corpus.new_index()
  @corpus.ingest(idx, [{ path: "input.bin", text }])
  let query = if argv.length() > 2 {
    argv[2]
  } else {
    ""
  }
  let matches = if query.length() > 0 {
    let hits = @corpus.search(idx, query, 20) catch {
      _ => []
    }
    @corpus.results_to_json(hits, [{ path: "input.bin", text }], query)
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
    parts.push("{\"api\":\"" + pair.0 + "\",\"count\":" + pair.1.to_string() + "}")
    i = i + 1
  }
  "[" + parts.join(",") + "]"
}