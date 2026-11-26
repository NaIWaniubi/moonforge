// gate: `moonforge-gate <old.json> <new.json> <policy.json>`

///|
fn fail_json(message : String) -> Unit {
  println("{\"error\":" + Json::string(message).stringify() + "}")
  @sys.exit(2)
}

///|
fn main {
  let argv = @env.args()
  if argv.length() < 4 {
    fail_json("usage: moonforge-gate <old.json> <new.json> <policy.json>")
  }
  let old_text = @fs.read_file_to_string(argv[1]) catch {
    @fs.IOError(message) => {
      fail_json("gate: cannot read old fact set: " + message)
      ""
    }
  }
  let new_text = @fs.read_file_to_string(argv[2]) catch {
    @fs.IOError(message) => {
      fail_json("gate: cannot read new fact set: " + message)
      ""
    }
  }
  let policy_text = @fs.read_file_to_string(argv[3]) catch {
    @fs.IOError(message) => {
      fail_json("gate: cannot read policy: " + message)
      ""
    }
  }
  let old = match @diff_lib.FactSet::from_json(old_text) {
    Ok(value) => value
    Err(error) => {
      fail_json("gate: invalid old fact set: " + error)
      { artifact_hash: "", facts: [], }
    }
  }
  let new = match @diff_lib.FactSet::from_json(new_text) {
    Ok(value) => value
    Err(error) => {
      fail_json("gate: invalid new fact set: " + error)
      { artifact_hash: "", facts: [], }
    }
  }
  let policy = match @policy_lib.parse_policy(policy_text) {
    Ok(value) => value
    Err(error) => {
      fail_json("gate: invalid policy: " + error)
      { rules: [], }
    }
  }
  let report = @diff_lib.diff(old, new)
  let result = @policy_lib.evaluate(report, policy)
  println(result.to_json())
  if result.passed {
    @sys.exit(0)
  } else {
    @sys.exit(1)
  }
}
