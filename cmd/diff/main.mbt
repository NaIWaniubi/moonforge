// diff: `moonforge-diff <old.json> <new.json> [--format json|sarif]`

///|
fn main {
  let argv = @env.args()
  if argv.length() < 3 {
    println("usage: moonforge-diff <old.json> <new.json> [--format json|sarif]")
    @sys.exit(2)
  }
  let mut format = "json"
  let mut i = 3
  while i < argv.length() {
    if argv[i] == "--format" && i + 1 < argv.length() {
      format = argv[i + 1]
      i = i + 2
    } else {
      println("diff: unexpected argument " + argv[i])
      @sys.exit(2)
    }
  }
  let old_text = @fs.read_file_to_string(argv[1]) catch {
    @fs.IOError(message) => {
      println("diff: cannot read old fact set: " + message)
      @sys.exit(2)
      ""
    }
  }
  let new_text = @fs.read_file_to_string(argv[2]) catch {
    @fs.IOError(message) => {
      println("diff: cannot read new fact set: " + message)
      @sys.exit(2)
      ""
    }
  }
  let old = match @diff_lib.FactSet::from_json(old_text) {
    Ok(value) => value
    Err(error) => {
      println("diff: invalid old fact set: " + error)
      @sys.exit(2)
      { artifact_hash: "", facts: [], }
    }
  }
  let new = match @diff_lib.FactSet::from_json(new_text) {
    Ok(value) => value
    Err(error) => {
      println("diff: invalid new fact set: " + error)
      @sys.exit(2)
      { artifact_hash: "", facts: [], }
    }
  }
  let report = @diff_lib.diff(old, new)
  if format == "sarif" {
    println(report.to_sarif())
  } else if format == "json" {
    println(report.to_json())
  } else {
    println("diff: unknown format " + format)
    @sys.exit(2)
  }
}
