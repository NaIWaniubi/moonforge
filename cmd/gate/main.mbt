// gate: `moonforge-gate <old.json> <new.json> <policy.json>`
fn main {
  let argv = @env.args()
  if argv.length() < 4 {
    println("usage: moonforge-gate <old.json> <new.json> <policy.json>")
    @sys.exit(2)
  }
  let old_text = @fs.read_file_to_string(argv[1]) catch {
    @fs.IOError(message) => {
      println("gate: cannot read old fact set: " + message)
      @sys.exit(2)
      ""
    }
  }
  let new_text = @fs.read_file_to_string(argv[2]) catch {
    @fs.IOError(message) => {
      println("gate: cannot read new fact set: " + message)
      @sys.exit(2)
      ""
    }
  }
  let policy_text = @fs.read_file_to_string(argv[3]) catch {
    @fs.IOError(message) => {
      println("gate: cannot read policy: " + message)
      @sys.exit(2)
      ""
    }
  }
  let old = match @diff_lib.FactSet::from_json(old_text) {
    Ok(value) => value
    Err(error) => {
      println("gate: invalid old fact set: " + error)
      @sys.exit(2)
      { artifact_hash: "", facts: [] }
    }
  }
  let new = match @diff_lib.FactSet::from_json(new_text) {
    Ok(value) => value
    Err(error) => {
      println("gate: invalid new fact set: " + error)
      @sys.exit(2)
      { artifact_hash: "", facts: [] }
    }
  }
  let policy = match @policy_lib.parse_policy(policy_text) {
    Ok(value) => value
    Err(error) => {
      println("gate: invalid policy: " + error)
      @sys.exit(2)
      { rules: [] }
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
