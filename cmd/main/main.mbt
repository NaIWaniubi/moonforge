// main: unified MoonForge CLI. Filesystem access lives here; all analysis
// packages remain pure and wasm-compilable.

///|
fn join(a : String, b : String) -> String {
  if a.length() == 0 {
    return b
  }
  let last = a[a.length() - 1]
  if last.to_int() == 47 || last.to_int() == 92 {
    a + b
  } else {
    a + "/" + b
  }
}

///|
fn collect(root : String, dir : String, prefix : String) -> Array[String] {
  let out : Array[String] = []
  let entries = @fs.read_dir(join(root, dir)) catch {
    @fs.IOError(_) => return out
  }
  let sorted : Array[String] = []
  for name in entries {
    sorted.push(name)
  }
  sorted.sort()
  for name in sorted {
    let rel = if prefix.length() == 0 { name } else { prefix + "/" + name }
    let full = join(root, rel)
    let is_dir = @fs.is_dir(full) catch { @fs.IOError(_) => false }
    if is_dir {
      for sub in collect(root, rel, rel) {
        out.push(sub)
      }
    } else {
      out.push(rel)
    }
  }
  out
}

///|
fn usage() -> String {
  [
    "usage: moonforge <command> [args]", "", "commands:", "  scan <dir> [--out <file>]",
    "  xref <file.exe> [--out <file>]", "  xref-v2 <file.exe> [--out <file>]", "  search <dir> <query...> [--limit N]",
    "  bundle <macho> [Info.plist]", "  wasmcheck <module.wasm>", "  diff <old.json> <new.json> [--format json|sarif]",
    "  gate <old.json> <new.json> <policy.json>",
  ].join("\n")
}

///|
/// Every failure leaves stdout as one machine-readable JSON value. Scripts can
/// parse failures exactly like successful reports; exit code 2 means usage or
/// input error, while gate violations use exit code 1.
fn fail_json(message : String) -> Unit {
  println("{\"error\":" + Json::string(message).stringify() + "}")
  @sys.exit(2)
}

///|
fn read_bytes(path : String) -> Bytes {
  @fs.read_file_to_bytes(path) catch {
    @fs.IOError(message) => {
      fail_json("cannot read " + path + ": " + message)
      Bytes::from_array([])
    }
  }
}

///|
fn read_string(path : String) -> String {
  @fs.read_file_to_string(path) catch {
    @fs.IOError(message) => {
      fail_json("cannot read " + path + ": " + message)
      ""
    }
  }
}

///|
fn write_or_print(text : String, out_path : String?) -> Unit {
  match out_path {
    Some(path) =>
      @fs.write_string_to_file(path, text) catch {
        @fs.IOError(message) =>
          fail_json("cannot write " + path + ": " + message)
      }
    None => println(text)
  }
}

///|
fn parse_int(text : String) -> Int32? {
  if text.length() == 0 {
    return None
  }
  let mut value = 0
  let mut i = 0
  while i < text.length() {
    let c = text[i].to_int()
    if c < 48 || c > 57 {
      return None
    }
    value = value * 10 + (c - 48)
    i = i + 1
  }
  Some(value)
}

///|
fn run_scan(argv : Array[String]) -> Unit {
  if argv.length() < 3 {
    fail_json(usage())
  }
  let root = argv[2]
  let mut out_path : String? = None
  let mut i = 3
  while i < argv.length() {
    if argv[i] == "--out" && i + 1 < argv.length() {
      out_path = Some(argv[i + 1])
      i = i + 2
    } else {
      fail_json("scan: unexpected argument " + argv[i])
    }
  }
  let root_is_dir = @fs.is_dir(root) catch { @fs.IOError(_) => false }
  if !root_is_dir {
    fail_json("scan: not a directory: " + root)
  }
  let paths = collect(root, "", "")
  let manifest = @core.Manifest::new()
  let mut unknown = 0
  for rel in paths {
    let data = read_bytes(join(root, rel))
    let rec = @core.record_of_bytes(rel, data)
    if rec.format == @core.Unknown {
      unknown = unknown + 1
    }
    manifest.push(rec)
  }
  write_or_print(manifest.to_json(), out_path)
}

///|
fn run_xref(argv : Array[String], v2 : Bool) -> Unit {
  if argv.length() < 3 {
    fail_json(usage())
  }
  let path = argv[2]
  let mut out_path : String? = None
  let mut i = 3
  while i < argv.length() {
    if argv[i] == "--out" && i + 1 < argv.length() {
      out_path = Some(argv[i + 1])
      i = i + 2
    } else {
      fail_json("xref: unexpected argument " + argv[i])
    }
  }
  let data = read_bytes(path)
  if v2 {
    let report = @peinfo.xref_v2_of(data)
    write_or_print(report.to_json(), out_path)
  } else {
    let table = @peinfo.xref_of(data)
    write_or_print(table.to_json(), out_path)
  }
}

///|
fn run_search(argv : Array[String]) -> Unit {
  if argv.length() < 4 {
    fail_json(usage())
  }
  let root = argv[2]
  let mut query = ""
  let mut limit : Int32 = 10
  let mut i = 3
  while i < argv.length() {
    if argv[i] == "--limit" && i + 1 < argv.length() {
      limit = match parse_int(argv[i + 1]) {
        Some(value) => value
        None => {
          fail_json("search: invalid limit " + argv[i + 1])
          10
        }
      }
      i = i + 2
    } else {
      if query.length() > 0 {
        query = query + " "
      }
      query = query + argv[i]
      i = i + 1
    }
  }
  if query.length() == 0 {
    fail_json(usage())
  }
  let root_is_dir = @fs.is_dir(root) catch { @fs.IOError(_) => false }
  if !root_is_dir {
    fail_json("search: not a directory: " + root)
  }
  let paths = collect(root, "", "")
  let docs : Array[@corpus.CorpusDoc] = []
  for rel in paths {
    let data = read_bytes(join(root, rel))
    docs.push({ path: rel, text: @corpus.strings_of(data, 4), })
  }
  let idx = @corpus.new_index()
  @corpus.ingest(idx, docs)
  let hits = @corpus.search(idx, query, limit) catch {
    _ => {
      fail_json("search: the query was rejected by the index")
      []
    }
  }
  println(@corpus.results_to_json(hits, docs, query))
}

///|
fn run_bundle(argv : Array[String]) -> Unit {
  if argv.length() < 3 {
    fail_json(usage())
  }
  let macho = read_bytes(argv[2])
  let plist = if argv.length() >= 4 { Some(read_bytes(argv[3])) } else { None }
  println(@bundle.bundle_profile(macho, plist).to_json())
}

///|
fn run_wasmcheck(argv : Array[String]) -> Unit {
  if argv.length() < 3 {
    fail_json(usage())
  }
  let data = read_bytes(argv[2])
  match @wasmcheck.wasm_report(data) {
    Ok(sections) => println(@wasmcheck.sections_to_json(sections))
    Err(error) => fail_json("wasmcheck: " + error)
  }
}

///|
fn run_diff(argv : Array[String]) -> Unit {
  if argv.length() < 4 {
    fail_json(usage())
  }
  let mut format = "json"
  let mut i = 4
  while i < argv.length() {
    if argv[i] == "--format" && i + 1 < argv.length() {
      format = argv[i + 1]
      i = i + 2
    } else {
      fail_json("diff: unexpected argument " + argv[i])
    }
  }
  let old = match @diff.FactSet::from_json(read_string(argv[2])) {
    Ok(value) => value
    Err(error) => {
      fail_json("diff: invalid old fact set: " + error)
      { artifact_hash: "", facts: [], }
    }
  }
  let new = match @diff.FactSet::from_json(read_string(argv[3])) {
    Ok(value) => value
    Err(error) => {
      fail_json("diff: invalid new fact set: " + error)
      { artifact_hash: "", facts: [], }
    }
  }
  let report = @diff.diff(old, new)
  if format == "sarif" {
    println(report.to_sarif())
  } else if format == "json" {
    println(report.to_json())
  } else {
    fail_json("diff: unknown format " + format)
  }
}

///|
fn run_gate(argv : Array[String]) -> Unit {
  if argv.length() < 5 {
    fail_json(usage())
  }
  let old = match @diff.FactSet::from_json(read_string(argv[2])) {
    Ok(value) => value
    Err(error) => {
      fail_json("gate: invalid old fact set: " + error)
      { artifact_hash: "", facts: [], }
    }
  }
  let new = match @diff.FactSet::from_json(read_string(argv[3])) {
    Ok(value) => value
    Err(error) => {
      fail_json("gate: invalid new fact set: " + error)
      { artifact_hash: "", facts: [], }
    }
  }
  let policy = match @policy.parse_policy(read_string(argv[4])) {
    Ok(value) => value
    Err(error) => {
      fail_json("gate: invalid policy: " + error)
      { rules: [], }
    }
  }
  let result = @policy.evaluate(@diff.diff(old, new), policy)
  println(result.to_json())
  if result.passed {
    @sys.exit(0)
  } else {
    @sys.exit(1)
  }
}

///|
fn main {
  let argv = @env.args()
  if argv.length() < 2 {
    fail_json(usage())
  }
  match argv[1] {
    "scan" => run_scan(argv)
    "xref" => run_xref(argv, false)
    "xref-v2" => run_xref(argv, true)
    "search" => run_search(argv)
    "bundle" => run_bundle(argv)
    "wasmcheck" => run_wasmcheck(argv)
    "diff" => run_diff(argv)
    "gate" => run_gate(argv)
    _ => fail_json("unknown command '" + argv[1] + "'\n" + usage())
  }
}
