///|
test "strings_of: keeps printable runs, drops binary noise" {
  let data : Bytes = b"\x00\x01VirtualAlloc\x00\x02\x03HeapAlloc\xff"
  let text = strings_of(data, 4)
  assert_true(text.contains("VirtualAlloc"))
  assert_true(text.contains("HeapAlloc"))
}

///|
test "strings_of: a run shorter than min_run is dropped" {
  let data : Bytes = b"ab\x00cd\x00efgh"
  assert_eq(strings_of(data, 4), "efgh")
}

///|
test "strings_of: binary noise alone yields no text" {
  let data : Bytes = b"\x00\xff\x01\x02\x03"
  assert_eq(strings_of(data, 4), "")
}

///|
test "search: a term present in one document hits exactly that document" {
  let idx = new_index()
  ingest(idx, [
    { path: "a.exe", text: "VirtualAlloc VirtualProtect" },
    { path: "b.exe", text: "HeapAlloc HeapFree" },
  ])
  let hits = search(idx, "VirtualAlloc", 10) catch {
    _ => []
  }
  assert_eq(hits.length(), 1)
  assert_eq(hits[0].0, "a.exe")
}

///|
test "search: a term in no document yields no hits, not a fake one" {
  let idx = new_index()
  ingest(idx, [{ path: "a.exe", text: "HeapAlloc" }])
  let hits = search(idx, "NonexistentSymbol", 10) catch {
    _ => []
  }
  assert_eq(hits.length(), 0)
}

///|
test "snippet: surrounds the match with ellipses when text is cut" {
  let text = "aaaaaaaaaaTARGETbbbbbbbbbb"
  match snippet(text, "TARGET", 3) {
    Some(s) => {
      assert_true(s.contains("TARGET"))
      assert_true(s.starts_with("…"))
      assert_true(s.ends_with("…"))
    }
    None => fail("expected a snippet")
  }
}

///|
test "snippet: absent term yields None, never an empty string" {
  let text = "nothing here"
  assert_eq(snippet(text, "TARGET", 3), None)
}

///|
test "snippet: case-insensitive match, original casing preserved" {
  let text = "xxVirtualAllocxx"
  match snippet(text, "virtualalloc", 4) {
    Some(s) => assert_true(s.contains("VirtualAlloc"))
    None => fail("expected a snippet")
  }
}