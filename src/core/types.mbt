///|
/// Container kind of one file in a scanned corpus.
pub(all) enum Format {
  Pe
  Elf
  MachO
  Wasm
  Plist
  Unknown
} derive(Eq, Debug)

///|
pub fn Format::label(self : Format) -> String {
  match self {
    Pe => "pe"
    Elf => "elf"
    MachO => "macho"
    Wasm => "wasm"
    Plist => "plist"
    Unknown => "unknown"
  }
}

///|
/// Lowercase label back to a Format. Only the six canonical labels are
/// accepted; anything else is a parse error at the manifest layer, never a
/// silent Unknown (an unknown label in a manifest is a corrupt manifest).
pub fn Format::from_label(label : String) -> Format? {
  match label {
    "pe" => Some(Pe)
    "elf" => Some(Elf)
    "macho" => Some(MachO)
    "wasm" => Some(Wasm)
    "plist" => Some(Plist)
    "unknown" => Some(Unknown)
    _ => None
  }
}

///|
/// Per-file structure counts, taken from the owning parser.
/// Unknown files carry zeros — they were never parsed.
pub(all) struct Summary {
  sections : Int32
  symbols : Int32
  imports : Int32
  exports : Int32
} derive(Eq, Debug)

///|
pub fn Summary::empty() -> Summary {
  { sections: 0, symbols: 0, imports: 0, exports: 0, }
}

///|
/// One scanned file. `sha256` is the lowercase hex digest, `None` only for
/// empty input (nothing to hash) — never a placeholder.
pub(all) struct FileRecord {
  path : String
  format : Format
  size : Int64
  sha256 : String?
  summary : Summary
  parse_status : String
} derive(Eq, Debug)

///|
pub(all) struct Manifest {
  files : Array[FileRecord]
}

///|
pub fn Manifest::new() -> Manifest {
  { files: [], }
}

///|
pub fn Manifest::push(self : Manifest, record : FileRecord) -> Unit {
  self.files.push(record)
}
