///|
/// Build the (slot_rva, api) table straight from the PE import descriptors.
///
/// Why this is read here rather than taken from a dependency: moonpe's
/// `Pe::iat()` advances slots by 16 bytes even in a 64-bit image, so from the
/// second descriptor on every slot address is wrong. Verified against objdump
/// on notepad.exe — the real IAT steps by 8 at 0x14002a440 / 448 / 450, while
/// moonpe reports 16-byte strides, which loses the 452 calls that land on
/// 0x14002a450. A wrong slot address silently misattributes calls, the one
/// failure mode this tool must not have. So the layout is decoded here, from
/// the PE specification:
///
///   Import Directory (data directory 1): a chain of 20-byte descriptors ending
///   in an all-zero entry.
///     +0  OriginalFirstThunk (hint/name table RVA)
///     +12 Name (DLL name RVA)
///     +16 FirstThunk (IAT RVA)
///   For i = 0,1,2,…: the IAT slot is FirstThunk + i*ptrsize and its hint/name
///   RVA comes from OriginalFirstThunk + i*ptrsize (falling back to FirstThunk
///   itself when the original thunk table is absent). A zero entry ends the
///   library. An entry with its high bit set (bit 63 / bit 31) is by-ordinal.
///|
/// Count nonzero entries in a thunk table (INT or IAT) at `rva`, stepping by
/// `ptr` bytes. Returns 0 when the table is unmapped; caps at 65536 so a
/// corrupt table cannot spin.
fn count_thunks(
  rva_to_off : (Int64) -> Int64,
  rva : Int64,
  ptr : Int,
  u32 : (Int) -> Int64,
  u64 : (Int) -> Int64,
) -> Int {
  let mut n = 0
  while n < 65536 {
    let off = rva_to_off(rva + (n * ptr).to_int64())
    if off < 0L {
      break
    }
    let raw = if ptr == 8 {
      u64(off.to_int())
    } else {
      u32(off.to_int())
    }
    if raw == 0L {
      break
    }
    n = n + 1
  }
  n
}

///|
fn iat_slots(data : Bytes) -> Array[(Int64, String)] {
  let out : Array[(Int64, String)] = []
  let pe = match @pe.parse(data) {
    Ok(pe) => pe
    Err(_) => return out
  }
  let u16 = fn(at : Int) -> Int {
    if at + 1 >= data.length() {
      return -1
    }
    data[at].to_int() | (data[at + 1].to_int() << 8)
  }
  let u32 = fn(at : Int) -> Int64 {
    if at + 3 >= data.length() {
      return -1L
    }
    data[at].to_int().to_int64() |
    (data[at + 1].to_int().to_int64() << 8) |
    (data[at + 2].to_int().to_int64() << 16) |
    (data[at + 3].to_int().to_int64() << 24)
  }
  let u64 = fn(at : Int) -> Int64 {
    let lo = u32(at)
    let hi = u32(at + 4)
    if lo < 0L || hi < 0L {
      return -1L
    }
    lo | (hi << 32)
  }
  let pe_off = u32(0x3C).to_int()
  if pe_off < 0 {
    return out
  }
  let opt = pe_off + 24
  let magic = u16(opt)
  let is64 = magic == 0x20B
  if !(is64) && magic != 0x10B {
    return out
  }
  let ptr = if is64 {
    8
  } else {
    4
  }
  // The optional header's data-directory array starts after a fixed prefix:
  // 112 bytes into a PE32+ optional header, 96 into a PE32 one.
  let dd = if is64 {
    opt + 112
  } else {
    opt + 96
  }
  let import_rva = u32(dd + 8)
  let import_size = u32(dd + 12)
  if import_rva <= 0L || import_size <= 0L {
    return out
  }
  let rva_to_off = fn(rva : Int64) -> Int64 {
    for sec in pe.sections {
      if rva >= sec.vaddr && rva < sec.vaddr + sec.size {
        return sec.offset + (rva - sec.vaddr)
      }
    }
    -1L
  }
  let read_name = fn(rva : Int64) -> String {
    let off = rva_to_off(rva)
    if off < 0L {
      return "#unreadable"
    }
    let mut pos = off.to_int()
    if pos + 2 > data.length() {
      return "#unreadable"
    }
    // Skip the 2-byte hint selector.
    pos = pos + 2
    let chars : Array[Char] = []
    while pos < data.length() && data[pos].to_int() != 0 {
      chars.push(data[pos].to_int().unsafe_to_char())
      pos = pos + 1
    }
    String::from_array(chars)
  }
  let desc = rva_to_off(import_rva)
  if desc < 0L {
    return out
  }
  let mut pos = desc.to_int()
  let mut minidesc = 0
  // A corrupt descriptor chain must not spin: cap the walk.
  while pos + 20 <= data.length() && minidesc < 4096 {
    minidesc = minidesc + 1
    let oft = u32(pos)
    let name_rva = u32(pos + 12)
    let ft = u32(pos + 16)
    if name_rva == 0L && ft == 0L {
      break
    }
    let thunk_table = if oft != 0L {
      oft
    } else {
      ft
    }
    // Two independent lengths bound a library's slot block:
    //   int_len — entries in the hint/name table (stops at the first zero);
    //   iat_len — nonzero slots in the IAT itself.
    // On a *bound* image the two disagree: notepad.exe's last descriptor has a
    // 1-entry INT while its IAT still holds 7 pre-bound addresses. Trusting
    // INT alone silently drops those slots (452 call sites on notepad), so the
    // block is taken as the longer of the two and any slot the INT cannot name
    // is labelled `#unresolved` rather than omitted.
    let int_len = count_thunks(rva_to_off, thunk_table, ptr, u32, u64)
    let iat_len = count_thunks(rva_to_off, ft, ptr, u32, u64)
    let n = if int_len > iat_len {
      int_len
    } else {
      iat_len
    }
    let mut i = 0
    while i < n {
      let entry_rva = thunk_table + (i * ptr).to_int64()
      let entry_off = rva_to_off(entry_rva)
      let api = if i >= int_len || entry_off < 0L {
        "#unresolved"
      } else {
        let raw = if ptr == 8 {
          u64(entry_off.to_int())
        } else {
          u32(entry_off.to_int())
        }
        let by_ordinal = if ptr == 8 {
          raw < 0L
        } else {
          (raw & 0x80000000L) != 0L
        }
        if by_ordinal {
          "#ordinal" + (raw & 0xFFFFL).to_string()
        } else {
          read_name(raw)
        }
      }
      out.push((ft + (i * ptr).to_int64(), api))
      i = i + 1
    }
    pos = pos + 20
  }
  // Delay-load imports live in data directory 13 and carry their own IATs.
  // Their slots are called exactly the same way, so they belong in the table;
  // leaving them out silently loses every delay-resolved call site.
  let delay_rva = u32(dd + 13 * 8)
  let delay_size = u32(dd + 13 * 8 + 4)
  if delay_rva > 0L && delay_size > 0L {
    let dbase = rva_to_off(delay_rva)
    if dbase >= 0L {
      let mut dpos = dbase.to_int()
      let mut dguard = 0
      // 32-byte descriptors: attributes, name, module, IAT, INT, bound, unload, ts
      while dpos + 32 <= data.length() && dguard < 512 {
        dguard = dguard + 1
        let name_rva = u32(dpos + 4)
        let iat_rva = u32(dpos + 12)
        let int_rva = u32(dpos + 16)
        if name_rva == 0L && iat_rva == 0L {
          break
        }
        let table = if int_rva != 0L {
          int_rva
        } else {
          iat_rva
        }
        let n = count_thunks(rva_to_off, table, ptr, u32, u64)
        let mut k = 0
        while k < n {
          let entry_off = rva_to_off(table + (k * ptr).to_int64())
          if entry_off < 0L {
            break
          }
          let raw = if ptr == 8 {
            u64(entry_off.to_int())
          } else {
            u32(entry_off.to_int())
          }
          let by_ordinal = if ptr == 8 {
            raw < 0L
          } else {
            (raw & 0x80000000L) != 0L
          }
          let api = if by_ordinal {
            "#ordinal" + (raw & 0xFFFFL).to_string()
          } else {
            read_name(raw)
          }
          out.push((iat_rva + (k * ptr).to_int64(), api))
          k = k + 1
        }
        dpos = dpos + 32
      }
    }
  }
  // build_xref binary-searches, so the table must be sorted by slot RVA.
  out.sort_by(fn(a, b) { a.0.compare(b.0) })
  out
}

///|
/// The `.text` bytes of a PE plus the virtual address of its first byte.
/// Sections not named `.text`, or with no raw content, are skipped.
fn text_of(data : Bytes) -> (Bytes, Int64) {
  let pe = match @pe.parse(data) {
    Ok(pe) => pe
    Err(_) => return (Bytes::from_array([]), 0L)
  }
  // Address space: moonbin reports section `vaddr` as an RVA (its .text is
  // 0x1000 on a 0x140000000 image) and moonpe reports IAT slots as RVAs too, so
  // the two sides already agree. Verified against objdump: the
  // `call *0x29175(%rip)` at RVA 0x12d5 lands on slot RVA 0x2a450.
  let parts : Array[Byte] = []
  let mut base : Int64 = 0L
  let mut first = true
  for sec in pe.sections {
    if sec.name != ".text" || sec.size <= 0L || sec.offset < 0L {
      continue
    }
    let start = sec.offset.to_int()
    let len = sec.size.to_int()
    if start < 0 || start + len > data.length() {
      continue
    }
    if first {
      base = sec.vaddr
      first = false
    }
    for i = start; i < start + len; i = i + 1 {
      parts.push(data[i])
    }
  }
  (Bytes::from_array(parts), base)
}


///|
/// Full pipeline for one PE image: IAT slots from the import and delay-import
/// descriptors, `.text` bytes, and the resolved call-site table.
pub fn xref_of(data : Bytes) -> @xref.XrefTable {
  let slots = iat_slots(data)
  let (code, base) = text_of(data)
  @xref.build_xref(slots, code, base)
}

///|
/// Just the slot count, for reporting without running the disassembler.
pub fn slot_count(data : Bytes) -> Int {
  iat_slots(data).length()
}

///|
/// Every executable section is decoded independently. The section flags, not
/// the name `.text`, decide what is code; each section keeps its own RVA base.
fn exec_sections(data : Bytes) -> Array[@xref.XrefSection] {
  let out : Array[@xref.XrefSection] = []
  let pe = match @pe.parse(data) {
    Ok(pe) => pe
    Err(_) => return out
  }
  for sec in pe.sections {
    if !sec.flags.contains("x") || sec.size <= 0L || sec.offset < 0L {
      continue
    }
    let start = sec.offset.to_int()
    if start < 0 || start >= data.length() {
      continue
    }
    let mut len = sec.size.to_int()
    if start + len > data.length() {
      len = data.length() - start
    }
    if len <= 0 {
      continue
    }
    let code = Bytes::makei(len, fn(i) { data[start + i] })
    out.push({ name: sec.name, base: sec.vaddr, code })
  }
  out
}

///|
/// Full v2 pipeline: import slots plus section-aware byte-derived call sites.
pub fn xref_v2_of(data : Bytes) -> @xref.XrefReportV2 {
  let slots = iat_slots(data)
  @xref.build_xref_v2(exec_sections(data), slots)
}

