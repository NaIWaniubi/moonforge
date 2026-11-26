// evidence: schema and digest tests.

test "empty digest is explicit" {
  assert_eq(
    @evidence.sha256_hex(b""),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  )
}

test "artifact keeps empty input honest" {
  let a = @evidence.artifact("empty.bin", b"", "unknown", "empty")
  assert_eq(a.sha256, None)
  assert_eq(a.parse_status, "empty")
}

test "evidence json is deterministic and escapes text" {
  let report : @evidence.EvidenceReport = {
    schema_version: "1",
    artifact: @evidence.artifact("a\"b", b"x", "pe", "parsed"),
    facts: [
      @evidence.fact(
        "f1",
        "import",
        "moonbin",
        @evidence.no_location(),
        "parsed",
        [("name", "VirtualAlloc")],
      ),
    ],
    diagnostics: [],
    stats: [("facts", "1")],
  }
  let json = report.to_json()
  assert_true(json.contains("\"path\":\"a\\\"b\""))
  assert_true(json.contains("\"schema_version\":\"1\""))
  assert_eq(json, report.to_json())
}
