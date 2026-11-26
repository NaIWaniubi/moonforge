// bundle: app-bundle profiling tests.

///|
test "bundle profile reads Info.plist identity" {
  let xml = b"<?xml version=\"1.0\"?><plist><dict><key>CFBundleIdentifier</key><string>org.example.demo</string><key>CFBundleShortVersionString</key><string>1.2.3</string></dict></plist>"
  let report = @bundle.bundle_profile(b"", Some(xml))
  match report.plist {
    Some(summary) => {
      assert_eq(summary.bundle_id, Some("org.example.demo"))
      assert_eq(summary.version, Some("1.2.3"))
      assert_eq(summary.keys, [
        "CFBundleIdentifier", "CFBundleShortVersionString",
      ])
    }
    None => fail("expected plist summary")
  }
}

///|
test "bundle profile is honest about missing inputs" {
  let report = @bundle.bundle_profile(b"", None)
  assert_eq(report.macho_format, "none")
  match report.plist {
    None => ()
    Some(_) => fail("missing plist must stay None")
  }
  assert_true(report.note.length() > 0)
}

///|
test "bundle profile rejects malformed plist without panicking" {
  let report = @bundle.bundle_profile(b"", Some(b"not a plist"))
  match report.plist {
    None => ()
    Some(_) => fail("malformed plist must not produce a summary")
  }
  assert_true(report.note.contains("rejected"))
}
