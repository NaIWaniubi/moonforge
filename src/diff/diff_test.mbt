// diff: deterministic diff tests.

///|
fn loc(offset : Int64) -> @diff.FactLocation {
  { section: ".text", rva: offset, va: offset, file_offset: offset, size: 1, }
}

///|
test "identical fact sets produce an empty diff" {
  let facts : Array[@diff.CanonicalFact] = [
    {
      kind: "import",
      key: "kernel32!VirtualAlloc",
      value: "rva",
      location: loc(1L),
    },
  ]
  let a : @diff.FactSet = { artifact_hash: "a", facts, }
  let b : @diff.FactSet = { artifact_hash: "b", facts: facts.copy(), }
  let report = @diff.diff(a, b)
  assert_eq(report.added.length(), 0)
  assert_eq(report.removed.length(), 0)
  assert_eq(report.changed.length(), 0)
}

///|
test "seeded added removed and changed facts are all detected" {
  let old : @diff.FactSet = {
    artifact_hash: "old",
    facts: [
      { kind: "import", key: "kernel32!Old", value: "1", location: loc(1L), },
      { kind: "export", key: "main", value: "old", location: loc(2L), },
    ],
  }
  let new : @diff.FactSet = {
    artifact_hash: "new",
    facts: [
      { kind: "import", key: "kernel32!New", value: "1", location: loc(3L), },
      { kind: "export", key: "main", value: "new", location: loc(2L), },
    ],
  }
  let report = @diff.diff(old, new)
  assert_eq(report.added.length(), 1)
  assert_eq(report.removed.length(), 1)
  assert_eq(report.changed.length(), 1)
  assert_eq(report.added[0].key, "kernel32!New")
  assert_eq(report.removed[0].key, "kernel32!Old")
  assert_eq(report.changed[0].key, "main")
}

///|
test "diff output is deterministic under input reordering" {
  let a : Array[@diff.CanonicalFact] = [
    { kind: "import", key: "b", value: "2", location: loc(2L), },
    { kind: "import", key: "a", value: "1", location: loc(1L), },
  ]
  let b : Array[@diff.CanonicalFact] = [
    { kind: "import", key: "a", value: "1", location: loc(1L), },
    { kind: "import", key: "b", value: "2", location: loc(2L), },
  ]
  let left : @diff.FactSet = { artifact_hash: "x", facts: a, }
  let right : @diff.FactSet = { artifact_hash: "y", facts: b, }
  assert_eq(
    @diff.diff(left, right).to_json(),
    @diff.diff(left, right).to_json(),
  )
}

///|
test "fact-set JSON round trip preserves normalized facts" {
  let text = "{\"artifact_hash\":\"h\",\"facts\":[{\"kind\":\"import\",\"key\":\"k\",\"value\":\"v\",\"location\":{\"section\":\".text\",\"rva\":1,\"va\":2,\"file_offset\":3,\"size\":4}}]}"
  match @diff.FactSet::from_json(text) {
    Ok(set) => {
      assert_eq(set.artifact_hash, "h")
      assert_eq(set.facts.length(), 1)
      assert_eq(set.facts[0].key, "k")
      assert_eq(set.facts[0].location.file_offset, 3L)
    }
    Err(error) => fail(error)
  }
}

///|
test "fact-set parser rejects missing or wrongly typed required fields" {
  let missing_location = "{\"artifact_hash\":\"h\",\"facts\":[{\"kind\":\"import\",\"key\":\"k\",\"value\":\"v\"}]}"
  match @diff.FactSet::from_json(missing_location) {
    Ok(_) => fail("missing location must be rejected")
    Err(_) => ()
  }
  let wrong_value = "{\"artifact_hash\":\"h\",\"facts\":[{\"kind\":\"import\",\"key\":\"k\",\"value\":7,\"location\":{\"section\":\"\",\"rva\":0,\"va\":0,\"file_offset\":0,\"size\":0}}]}"
  match @diff.FactSet::from_json(wrong_value) {
    Ok(_) => fail("non-string value must be rejected")
    Err(_) => ()
  }
}

///|
test "SARIF output carries required result and tool fields" {
  let report : @diff.DiffReport = {
    added: [
      {
        change: "added",
        kind: "import",
        key: "kernel32!VirtualAlloc",
        old_value: "",
        new_value: "rva",
        old_location: None,
        new_location: Some(loc(1L)),
      },
    ],
    removed: [],
    changed: [],
  }
  let sarif = report.to_sarif()
  assert_true(sarif.contains("\"version\":\"2.1.0\""))
  assert_true(sarif.contains("\"ruleId\":\"diff-added\""))
  assert_true(sarif.contains("\"message\""))
  assert_true(sarif.contains("\"locations\""))
  assert_true(sarif.contains("\"properties\""))
}
