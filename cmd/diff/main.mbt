// diff: `moonforge-diff <old.json> <new.json> [--format json|sarif]`

///|
fn fail_json(message : String) -> Unit {
  println("{\"error\":" + Json::string(message).stringify() + "}")
  @sys.exit(2)
}

///|
fn main {
  let argv = @env.args()
  if argv.length() < 3 {
    fail_json(
      "usage: moonforge-diff <old.json> <new.json> [--format json|sarif]",
    )
  }
  let mut format = "json"
  let mut i = 3
  while i < argv.length() {
    if argv[i] == "--format" && i + 1 < argv.length() {
      format = argv[i + 1]
      i = i + 2
    } else {
      fail_json("diff: unexpected argument " + argv[i])
    }
  }
  let old_text = @fs.read_file_to_string(argv[1]) catch {
    @fs.IOError(message) => {
      fail_json("diff: cannot read old fact set: " + message)
      ""
    }
  }
  let new_text = @fs.read_file_to_string(argv[2]) catch {
    @fs.IOError(message) => {
      fail_json("diff: cannot read new fact set: " + message)
      ""
    }
  }
  let old = match @diff_lib.FactSet::from_json(old_text) {
    Ok(value) => value
    Err(error) => {
      fail_json("diff: invalid old fact set: " + error)
      { artifact_hash: "", facts: [], }
    }
  }
  let new = match @diff_lib.FactSet::from_json(new_text) {
    Ok(value) => value
    Err(error) => {
      fail_json("diff: invalid new fact set: " + error)
      { artifact_hash: "", facts: [], }
    }
  }
  let report = @diff_lib.diff(old, new)
  if format == "sarif" {
    println(report.to_sarif())
  } else if format == "json" {
    println(report.to_json())
  } else {
    fail_json("diff: unknown format " + format)
  }
}
