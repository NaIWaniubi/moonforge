///|
/// Operand parsing is the only place a wrong answer would silently misattribute
/// a call, so every accepted and refused shape is pinned.
test "call_target: direct hex targets" {
  assert_eq(call_target("0x140001234", 0L), Some(0x140001234L))
  assert_eq(call_target("0x0", 0L), Some(0L))
  assert_eq(call_target("0xABC", 0L), Some(0xABCL))
}

///|
/// The shape that real x86-64 binaries actually use for imports:
/// `call qword ptr [rip+0x29175]`. Known-good value comes from objdump on
/// notepad.exe — `1400012d5: ff 15 75 91 02 00  call *0x29175(%rip) # 0x14002a450`
/// where the instruction ends at 0x1400012db, so 0x1400012db + 0x29175 lands on
/// the IAT slot at 0x14002a450.
test "call_target: rip-relative import thunk resolves to the IAT slot" {
  let insn_end = 0x1400012dbL
  assert_eq(
    call_target("qword ptr [rip+0x29175]", insn_end),
    Some(0x14002a450L),
  )
  // Negative displacement form.
  assert_eq(
    call_target("qword ptr [rip-0x10]", insn_end),
    Some(insn_end - 16L),
  )
}

///|
test "call_target: anything without a static target is refused" {
  // Registers and non-rip memory operands have no static target.
  assert_eq(call_target("rax", 0L), None)
  assert_eq(call_target("qword ptr [rax]", 0L), None)
  assert_eq(call_target("qword ptr [rax+0x10]", 0L), None)
  // Malformed hex must not be partially parsed.
  assert_eq(call_target("0x", 0L), None)
  assert_eq(call_target("0x12G4", 0L), None)
  assert_eq(call_target("", 0L), None)
  assert_eq(call_target("140001234", 0L), None)
  // A bare [rip] has no displacement we are willing to invent.
  assert_eq(call_target("qword ptr [rip]", 0x1000L), None)
}

///|
/// The whole point of the join: a call that lands on an import slot is
/// attributed; a call that lands elsewhere is counted, not dropped; an
/// indirect call is counted as unstatically-resolvable.
test "build_xref: resolves slots, counts unresolved and indirect" {
  // call 0x1010 (rel32 = 0x1010 - 0x1005 = 0x0B) then call 0x0F000000+... —
  // build the bytes by hand: E8 <rel32>.
  // At 0x1000: E8 0B 00 00 00   -> call 0x1010
  // At 0x1005: E8 06 00 00 00   -> call 0x1010
  // At 0x100A: FF D0            -> call rax (indirect)
  // At 0x100C: E8 EF 0F 00 00   -> call 0x2000 (no slot there)
  let code : Bytes = Bytes::from_array([
    0xE8, 0x0B, 0x00, 0x00, 0x00,
    0xE8, 0x06, 0x00, 0x00, 0x00,
    0xFF, 0xD0,
    0xE8, 0xEF, 0x0F, 0x00, 0x00,
  ].map(fn(v) { v.to_byte() }))
  let slots : Array[(Int64, String)] = [(0x1010L, "VirtualAlloc")]
  let table = build_xref(slots, code, 0x1000L)
  assert_eq(table.by_api.length(), 1)
  assert_eq(table.by_api[0], ("VirtualAlloc", 2))
  assert_eq(table.sites.length(), 2)
  assert_eq(table.sites[0].call_addr, 0x1000L)
  assert_eq(table.sites[1].call_addr, 0x1005L)
  assert_eq(table.unresolved, 1)
  assert_eq(table.indirect_calls, 1)
}

///|
test "build_xref: no slots means no attributions, and that is reported" {
  let code : Bytes = Bytes::from_array(
    [0xE8, 0x00, 0x00, 0x00, 0x00].map(fn(v) { v.to_byte() }),
  )
  let table = build_xref([], code, 0x1000L)
  assert_eq(table.sites.length(), 0)
  assert_eq(table.by_api.length(), 0)
  // The call itself is still seen; it just could not be attributed.
  assert_eq(table.unresolved, 1)
}

///|
test "build_xref: counts are sorted by api name, stable across runs" {
  let code : Bytes = Bytes::from_array([
    0xE8, 0x0B, 0x00, 0x00, 0x00,
    0xE8, 0x06, 0x00, 0x00, 0x00,
  ].map(fn(v) { v.to_byte() }))
  let slots : Array[(Int64, String)] = [(0x1010L, "ZwClose")]
  let a = build_xref(slots, code, 0x1000L)
  let b = build_xref(slots, code, 0x1000L)
  assert_eq(a.to_json(), b.to_json())
}

///|
test "json: xref shape carries the honesty fields" {
  let table : XrefTable = {
    by_api: [("VirtualAlloc", 2)],
    sites: [{ api: "VirtualAlloc", call_addr: 0x1000L, target_addr: 0x1010L }],
    unresolved: 3,
    indirect_calls: 1,
  }
  let json = table.to_json()
  assert_true(json.contains("\"unresolved\":3"))
  assert_true(json.contains("\"indirect_calls\":1"))
  assert_true(json.contains("\"count\":2"))
}

///|
/// xref v2 derives targets from bytes and keeps a complete call ledger.
test "xref v2: byte-derived E8 and FF15 attribution" {
  let code : Bytes = Bytes::from_array([
    0xE8, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xD0,
  ].map(fn(v) { v.to_byte() }))
  let slots : Array[(Int64, String)] = [
    (0x1005L, "VirtualAlloc"),
    (0x100BL, "VirtualFree"),
  ]
  let report = build_xref_v2([{ name: ".text", base: 0x1000L, code }], slots)
  assert_eq(report.sites.length(), 2)
  assert_eq(report.sites[0].api, "VirtualAlloc")
  assert_eq(report.sites[0].rule, "E8-rel32")
  assert_eq(report.sites[1].api, "VirtualFree")
  assert_eq(report.sites[1].rule, "FF15-rip-rel32")
  assert_eq(report.decoded_calls, 3)
  assert_eq(report.direct_calls, 2)
  assert_eq(report.indirect_calls, 1)
  assert_eq(report.unresolved_direct, 0)
  assert_eq(
    report.decoded_calls,
    report.sites.length() + report.unresolved_direct + report.indirect_calls,
  )
}

///|
/// Every executable section keeps its own base; addresses never leak across
/// section boundaries.
test "xref v2: multiple sections retain independent bases" {
  let a : Bytes = Bytes::from_array([0xE8, 0x00, 0x00, 0x00, 0x00].map(fn(v) { v.to_byte() }))
  let b : Bytes = Bytes::from_array([0xE8, 0x00, 0x00, 0x00, 0x00].map(fn(v) { v.to_byte() }))
  let report = build_xref_v2(
    [
      { name: ".text", base: 0x1000L, code: a },
      { name: ".code2", base: 0x2000L, code: b },
    ],
    [(0x1005L, "ApiA"), (0x2005L, "ApiB")],
  )
  assert_eq(report.sites.length(), 2)
  assert_eq(report.sites[0].section, ".text")
  assert_eq(report.sites[0].rva, 0L)
  assert_eq(report.sites[1].section, ".code2")
  assert_eq(report.sites[1].rva, 0L)
  assert_eq(report.sections_scanned, 2)
}

