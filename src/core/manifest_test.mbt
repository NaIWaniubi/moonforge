///|
/// Format detection from magic bytes. These are the six branch points the
/// scan command relies on, so each one is pinned to real leading bytes.
test "detect: MZ peeks as PE" {
  let data : Bytes = b"MZ\x90\x00\x03\x00\x00\x00"
  assert_eq(@core.detect_format(data), @core.Pe)
}

///|
test "detect: ELF magic" {
  let data : Bytes = b"\x7fELF\x02\x01\x01\x00"
  assert_eq(@core.detect_format(data), @core.Elf)
}

///|
test "detect: Mach-O magics, both endians, 32 and 64" {
  assert_eq(@core.detect_format(b"\xfe\xed\xfa\xce"), @core.MachO)
  assert_eq(@core.detect_format(b"\xfe\xed\xfa\xcf"), @core.MachO)
  assert_eq(@core.detect_format(b"\xce\xfa\xed\xfe"), @core.MachO)
  assert_eq(@core.detect_format(b"\xcf\xfa\xed\xfe"), @core.MachO)
}

///|
test "detect: fat Mach-O header" {
  assert_eq(
    @core.detect_format(b"\xca\xfe\xba\xbe\x00\x00\x00\x02"),
    @core.MachO,
  )
}

///|
test "detect: WASM magic and version" {
  assert_eq(@core.detect_format(b"\x00asm\x01\x00\x00\x00"), @core.Wasm)
  assert_eq(@core.detect_format(b"\x00asm\x02\x00\x00\x00"), @core.Unknown)
}

///|
test "detect: XML and binary plist" {
  assert_eq(
    @core.detect_format(b"<?xml version=\"1.0\"?><plist/>"),
    @core.Plist,
  )
  assert_eq(@core.detect_format(b"<plist version=\"1.0\"/>"), @core.Plist)
  assert_eq(@core.detect_format(b"bplist00\x00"), @core.Plist)
}

///|
test "detect: everything else is Unknown, never guessed" {
  assert_eq(@core.detect_format(b"hello, world\n"), @core.Unknown)
  assert_eq(@core.detect_format(b""), @core.Unknown)
  assert_eq(@core.detect_format(b"M"), @core.Unknown)
  assert_eq(@core.detect_format(b"\x7fEL"), @core.Unknown)
}

///|
test "format labels round-trip and junk labels are refused" {
  for
    f in [
      @core.Pe,
      @core.Elf,
      @core.MachO,
      @core.Wasm,
      @core.Plist,
      @core.Unknown,
    ] {
    assert_eq(Format::from_label(f.label()), Some(f))
  }
  assert_eq(Format::from_label("PE"), None)
  assert_eq(Format::from_label("pe32"), None)
  assert_eq(Format::from_label(""), None)
}

///|
test "record: unknown file keeps zero counts and a real digest" {
  let rec = @core.record_of_bytes("notes.txt", b"hello")
  assert_eq(rec.format, @core.Unknown)
  assert_eq(rec.size, 5L)
  assert_eq(rec.summary.sections, 0)
  assert_eq(rec.parse_status, "unsupported")
  // sha256("hello") — the well-known value, not a placeholder.
  assert_eq(
    rec.sha256,
    Some("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"),
  )
}

///|
test "record: empty input has no digest and no size" {
  let rec = @core.record_of_bytes("empty", b"")
  assert_eq(rec.sha256, None)
  assert_eq(rec.size, 0L)
  assert_eq(rec.format, @core.Unknown)
  assert_eq(rec.parse_status, "empty")
}

///|
test "record: malformed recognized container is not reported as parsed" {
  let rec = @core.record_of_bytes("truncated.exe", b"MZ\x90\x00")
  assert_eq(rec.format, @core.Pe)
  assert_eq(rec.parse_status, "malformed")
  assert_eq(rec.summary.sections, 0)
}

///|
test "record: WASM is parsed, and a truncated module is malformed" {
  let valid = @core.record_of_bytes("empty.wasm", b"\x00asm\x01\x00\x00\x00")
  assert_eq(valid.format, @core.Wasm)
  assert_eq(valid.parse_status, "parsed")
  assert_eq(valid.summary.sections, 0)
  let truncated = @core.record_of_bytes(
    "truncated.wasm", b"\x00asm\x01\x00\x00\x00\x01\x05",
  )
  assert_eq(truncated.format, @core.Wasm)
  assert_eq(truncated.parse_status, "malformed")
}

///|
test "record: plist is parsed, and malformed XML is refused" {
  let valid = @core.record_of_bytes(
    "Info.plist", b"<?xml version=\"1.0\"?><plist version=\"1.0\"><dict/></plist>",
  )
  assert_eq(valid.format, @core.Plist)
  assert_eq(valid.parse_status, "parsed")
  let malformed = @core.record_of_bytes(
    "bad.plist", b"<?xml version=\"1.0\"?><plist>",
  )
  assert_eq(malformed.format, @core.Plist)
  assert_eq(malformed.parse_status, "malformed")
}

///|
test "json: manifest round-trips through the canonical shape" {
  let m = Manifest::new()
  m.push(@core.record_of_bytes("a.bin", b"MZ\x90\x00"))
  m.push(@core.record_of_bytes("b.txt", b"plain"))
  let text = m.to_json()
  match @core.Manifest::from_json(text) {
    Ok(back) => {
      assert_eq(back.files.length(), 2)
      assert_eq(back.files[0].path, "a.bin")
      assert_eq(back.files[0].format, @core.Pe)
      assert_eq(back.files[1].path, "b.txt")
      assert_eq(back.files[1].format, @core.Unknown)
      assert_eq(back.files[1].sha256, m.files[1].sha256)
      assert_eq(back.files[0].parse_status, m.files[0].parse_status)
      assert_eq(back.files[1].parse_status, m.files[1].parse_status)
    }
    Err(msg) => fail("reparse failed: " + msg)
  }
}

///|
test "json: paths with quotes and control characters survive the trip" {
  let m = Manifest::new()
  m.push(@core.record_of_bytes("weird\"name\\with\ttab", b"x"))
  match @core.Manifest::from_json(m.to_json()) {
    Ok(back) => assert_eq(back.files[0].path, "weird\"name\\with\ttab")
    Err(msg) => fail("reparse failed: " + msg)
  }
}

///|
test "json: a corrupt manifest is refused, not repaired" {
  let refused = fn(r : Result[Manifest, String]) -> Bool {
    match r {
      Ok(_) => false
      Err(_) => true
    }
  }
  assert_true(refused(@core.Manifest::from_json("")))
  assert_true(refused(@core.Manifest::from_json("{\"files\":[}")))
  // A format label we never write must not silently become @core.Unknown.
  assert_true(
    refused(
      @core.Manifest::from_json(
        "{\"files\":[{\"path\":\"x\",\"format\":\"coff\",\"size\":1,\"sha256\":null,\"summary\":{\"sections\":0,\"symbols\":0,\"imports\":0,\"exports\":0}}]",
      ),
    ),
  )
}
