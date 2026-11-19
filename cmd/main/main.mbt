// main: `moonforge scan <dir> [--out file]`
//
// Walks a directory, hashes and profiles every regular file, and writes the
// canonical manifest. Directories are walked depth-first; symlinks are read as
// their target content (no recursion minidesc needed: read_dir returns entries,
// and a symlinked directory is reported by is_dir, which we skip unless it is
// the root).

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
/// Depth-first file collection. Returns paths relative to `root_prefix`.
fn collect(root : String, dir : String, prefix : String) -> Array[String] {
  let out : Array[String] = []
  let entries = @fs.read_dir(join(root, dir)) catch {
    @fs.IOError(_) => return out
  }
  // Sort for a stable manifest: two runs over the same tree must byte-match.
  let sorted : Array[String] = []
  for name in entries {
    sorted.push(name)
  }
  sorted.sort()
  for name in sorted {
    let rel = if prefix.length() == 0 {
      name
    } else {
      prefix + "/" + name
    }
    let full = join(root, rel)
    let is_dir = @fs.is_dir(full) catch {
      @fs.IOError(_) => false
    }
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
fn usage() -> Unit {
  let lines : Array[String] = [
    "usage: moonforge scan <dir> [--out <file>]",
    "",
    "Scans a directory and writes a manifest of every file:",
    "container format, size, sha256, and section/symbol/import/export counts.",
    "Files whose magic is not PE / ELF / Mach-O are recorded as `unknown`",
    "and are never handed to a parser.",
    "",
    "usage: moonforge xref <file.exe> [--out <file>]",
    "",
    "Resolves imported-API call sites in one PE: which import is called from",
    "where. Only statically-encoded `call rel32` participates; indirect calls",
    "are counted, not guessed.",
    "",
    "usage: moonforge search <dir> <query...> [--limit N]",
    "",
    "Indexes the printable text of every file under <dir> and ranks them for",
    "the query. Each hit carries a snippet around the match.",
  ]
  println(lines.join("\n"))
}

///|
fn run_xref(argv : Array[String]) -> Unit raise {
  if argv.length() < 3 {
    usage()
    @sys.exit(2)
  }
  let path = argv[2]
  let mut out_path : String? = None
  let mut i = 3
  while i < argv.length() {
    if argv[i] == "--out" && i + 1 < argv.length() {
      out_path = Some(argv[i + 1])
      i = i + 2
    } else {
      println("moonforge xref: unexpected argument '" + argv[i] + "'")
      @sys.exit(2)
    }
  }
  let data = @fs.read_file_to_bytes(path) catch {
    @fs.IOError(msg) => {
      println("moonforge xref: cannot read " + path + ": " + msg)
      @sys.exit(2)
      Bytes::from_array([])
    }
  }
  let table = @peinfo.xref_of(data)
  let slots_n = @peinfo.slot_count(data)
  let json = table.to_json()
  match out_path {
    Some(p) => @fs.write_string_to_file(p, json)
    None => println(json)
  }
  println(
    "xref: " +
    slots_n.to_string() +
    " IAT slots, " +
    table.sites.length().to_string() +
    " resolved call sites, " +
    table.unresolved.to_string() +
    " unresolved, " +
    table.indirect_calls.to_string() +
    " indirect",
  )
}

///|
fn run_search(argv : Array[String]) -> Unit raise {
  if argv.length() < 4 {
    usage()
    @sys.exit(2)
  }
  let root = argv[2]
  let mut query = ""
  let limit : Int32 = 10
  let mut i = 3
  while i < argv.length() {
    if false {
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
    usage()
    @sys.exit(2)
  }
  let root_is_dir = @fs.is_dir(root) catch {
    @fs.IOError(_) => false
  }
  if not(root_is_dir) {
    println("moonforge search: not a directory: " + root)
    @sys.exit(2)
    return
  }
  let paths = collect(root, "", "")
  let docs : Array[@corpus.CorpusDoc] = []
  for rel in paths {
    let data = @fs.read_file_to_bytes(join(root, rel)) catch {
      @fs.IOError(_) => continue
    }
    docs.push({ path: rel, text: @corpus.strings_of(data, 4) })
  }
  let idx = @corpus.new_index()
  @corpus.ingest(idx, docs)
  let hits = @corpus.search(idx, query, limit) catch {
    _ => {
      println("moonforge search: the query was rejected by the index")
      @sys.exit(2)
      []
    }
  }
  println(@corpus.results_to_json(hits, docs, query))
  println("search: " + hits.length().to_string() + " hits over " + docs.length().to_string() + " files")
}

///|
fn main raise {
  let argv = @env.args()
  if argv.length() < 3 {
    usage()
    @sys.exit(2)
  }
  if argv[1] == "search" {
    run_search(argv)
    return
  }
  if argv[1] == "xref" {
    run_xref(argv)
    return
  }
  if argv[1] != "scan" {
    println("moonforge: unknown command '" + argv[1] + "'")
    usage()
    @sys.exit(2)
  }
  let root = argv[2]
  let mut out_path : String? = None
  let mut i = 3
  while i < argv.length() {
    if argv[i] == "--out" && i + 1 < argv.length() {
      out_path = Some(argv[i + 1])
      i = i + 2
    } else if argv[i] == "--help" {
      usage()
      @sys.exit(0)
    } else {
      println("moonforge: unexpected argument '" + argv[i] + "'")
      @sys.exit(2)
    }
  }
  let root_is_dir = @fs.is_dir(root) catch {
    @fs.IOError(_) => false
  }
  if not(root_is_dir) {
    println("moonforge: not a directory: " + root)
    @sys.exit(2)
  }
  let paths = collect(root, "", "")
  let manifest = @core.Manifest::new()
  let mut unknown = 0
  for rel in paths {
    let data = @fs.read_file_to_bytes(join(root, rel)) catch {
      @fs.IOError(msg) => {
        println("moonforge: skip " + rel + ": " + msg)
        continue
      }
    }
    let rec = @core.record_of_bytes(rel, data)
    if rec.format == @core.Unknown {
      unknown = unknown + 1
    }
    manifest.push(rec)
  }
  let text = manifest.to_json()
  match out_path {
    Some(path) => {
      @fs.write_string_to_file(path, text) catch {
        @fs.IOError(msg) => {
          println("moonforge: cannot write " + path + ": " + msg)
          @sys.exit(2)
        }
      }
      println(
        "scan: " +
        manifest.files.length().to_string() +
        " files (" +
        unknown.to_string() +
        " unknown) -> " +
        path,
      )
    }
    None => println(text)
  }
}