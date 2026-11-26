// policy: parser and gate tests.

///|
test "policy parser accepts documented rules" {
  let text = "{\"rules\":[{\"id\":\"no-new-import\",\"kind\":\"import\",\"change\":\"added\",\"key_prefix\":\"kernel32!\",\"severity\":\"high\"}]}"
  match @policy.parse_policy(text) {
    Ok(policy) => {
      assert_eq(policy.rules.length(), 1)
      assert_eq(policy.rules[0].id, "no-new-import")
      assert_eq(policy.rules[0].key_prefix, "kernel32!")
    }
    Err(error) => fail(error)
  }
}

///|
test "gate blocks seeded added import and passes clean diff" {
  let policy = match
    @policy.parse_policy(
      "{\"rules\":[{\"id\":\"no-new-import\",\"kind\":\"import\",\"change\":\"added\",\"key_prefix\":\"kernel32!\",\"severity\":\"high\"}]}",
    ) {
    Ok(value) => value
    Err(error) => fail(error)
  }
  let bad : @diff.DiffReport = {
    added: [
      {
        change: "added",
        kind: "import",
        key: "kernel32!VirtualAlloc",
        old_value: "",
        new_value: "rva",
        old_location: None,
        new_location: None,
      },
    ],
    removed: [],
    changed: [],
  }
  let result = @policy.evaluate(bad, policy)
  assert_false(result.passed)
  assert_eq(result.violations.length(), 1)
  let clean : @diff.DiffReport = { added: [], removed: [], changed: [], }
  assert_true(@policy.evaluate(clean, policy).passed)
}

///|
test "policy parser rejects malformed rules instead of failing open" {
  let bad_change = "{\"rules\":[{\"id\":\"x\",\"change\":\"addeed\"}]}"
  match @policy.parse_policy(bad_change) {
    Ok(_) => fail("typo in change must be rejected")
    Err(_) => ()
  }
  let missing_id = "{\"rules\":[{\"kind\":\"import\"}]}"
  match @policy.parse_policy(missing_id) {
    Ok(_) => fail("missing id must be rejected")
    Err(_) => ()
  }
}
