// wasmcheck: positive and negative structural parser tests.

///|
test "wasm report accepts a minimal module" {
  let wasm = b"\x00asm\x01\x00\x00\x00"
  match @wasmcheck.wasm_report(wasm) {
    Ok(sections) => assert_eq(sections.length(), 0)
    Err(error) => fail(error)
  }
}

///|
test "wasm report rejects bad magic with a reason" {
  let bad = b"\x00asx\x01\x00\x00\x00"
  match @wasmcheck.wasm_report(bad) {
    Ok(_) => fail("bad magic must be rejected")
    Err(error) => assert_true(error.length() > 0)
  }
}

///|
test "wasm report rejects truncated input" {
  match @wasmcheck.wasm_report(b"\x00asm") {
    Ok(_) => fail("truncated header must be rejected")
    Err(error) => assert_true(error.length() > 0)
  }
}
