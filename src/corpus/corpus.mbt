// corpus: index every scanned file and search across them.
//
// The value over `grep -r`: a binary's searchable text is not a grep-friendly
// stream — it is scattered printable runs inside section data, mixed with
// symbol names and section names. This layer extracts that text once, feeds it
// to the moonseek index, and exposes ranked search with snippets. No filesystem
// access here: callers hand in (path, text) pairs, so this compiles to wasm too.

///|
/// The declared fields. `path` is weighted higher than `body` because a hit in
/// the file name is almost always the more useful answer than a hit in a byte
/// run that happens to contain the word.
pub fn new_index() -> @moonseek.Index {
  @moonseek.Index::new([
    { name: "path", weight: 3.0 },
    { name: "body", weight: 1.0 },
  ])
}

///|
/// One indexed document: a file path and its extracted text.
pub(all) struct CorpusDoc {
  path : String
  text : String
} derive(Debug)

///|
/// Printable ASCII runs of at least `min_run` characters, joined by a space.
///
/// Why not decode UTF-8: binary payloads are not UTF-8, and a lossy decode both
/// invents characters and hides ASCII runs behind replacement glyphs. This
/// keeps only what a human could read in a hex dump, which is exactly what an
/// analyst greps for.
pub fn strings_of(data : Bytes, min_run : Int) -> String {
  let out : Array[Char] = []
  let run : Array[Char] = []
  for i = 0; i < data.length(); i = i + 1 {
    let b = data[i].to_int()
    let printable = (b >= 0x20 && b < 0x7F) || b == 9 || b == 10 || b == 13
    if printable {
      run.push(b.unsafe_to_char())
    } else {
      if run.length() >= min_run {
        for c in run {
          out.push(c)
        }
        out.push(' ')
      }
      run.clear()
    }
  }
  if run.length() >= min_run {
    for c in run {
      out.push(c)
    }
  }
  String::from_array(out)
}

///|
/// Add every document. Re-adding a path replaces it (moonseek's contract).
pub fn ingest(idx : @moonseek.Index, docs : Array[CorpusDoc]) -> Unit {
  for d in docs {
    idx.add({ id: d.path, fields: [("path", d.path), ("body", d.text)] })
  }
}

///|
/// Ranked search. Returns (path, score) pairs in the index's order.
pub fn search(
  idx : @moonseek.Index,
  query : String,
  limit : Int32,
) -> Array[(String, Double)] raise @moonseek.QueryError {
  let hits = idx.search(query, limit~)
  let out : Array[(String, Double)] = []
  for h in hits {
    out.push((h.id, h.score))
  }
  out
}

///|
/// A snippet: the window of `text` around the first occurrence of `term`,
/// with `…` marking text cut off on either side. Returns None when the term is
/// absent — never an empty string standing in for "not found".
pub fn snippet(text : String, term : String, radius : Int) -> String? {
  let at = index_of_ci(text, term)
  if at < 0 {
    return None
  }
  let start = if at > radius {
    at - radius
  } else {
    0
  }
  let mut stop = at + term.length() + radius
  if stop > text.length() {
    stop = text.length()
  }
  // Snap to char boundaries; the text here is ASCII runs, so this is direct.
  let body = text[start:stop].to_owned()
  let mut out = ""
  if start > 0 {
    out = out + "…"
  }
  out = out + body
  if stop < text.length() {
    out = out + "…"
  }
  Some(out)
}

///|
fn index_of_ci(haystack : String, needle : String) -> Int {
  if needle.length() == 0 {
    return -1
  }
  let mut i = 0
  while i + needle.length() <= haystack.length() {
    let mut j = 0
    let mut same = true
    while j < needle.length() {
      if lower_int(haystack[i + j].to_int()) != lower_int(needle[j].to_int()) {
        same = false
        break
      }
      j = j + 1
    }
    if same {
      return i
    }
    i = i + 1
  }
  -1
}

///|
fn lower_int(v : Int) -> Int {
  if v >= 65 && v <= 90 {
    v + 32
  } else {
    v
  }
}

///|
pub fn results_to_json(hits : Array[(String, Double)], docs : Array[CorpusDoc], term : String) -> String {
  let parts : Array[String] = []
  for pair in hits {
    let mut text = ""
    for d in docs {
      if d.path == pair.0 {
        text = d.text
      }
    }
    let snip = match snippet(text, term, 40) {
      Some(s) => s
      None => ""
    }
    parts.push(
      "{\"path\":\"" +
      escape(pair.0) +
      "\",\"score\":" +
      pair.1.to_string() +
      ",\"snippet\":\"" +
      escape(snip) +
      "\"}",
    )
  }
  "[" + parts.join(",") + "]"
}

///|
fn escape(s : String) -> String {
  let out : Array[Char] = []
  for c in s {
    let v = c.to_int()
    if v == 34 {
      out.push('\\')
      out.push('"')
    } else if v == 92 {
      out.push('\\')
      out.push('\\')
    } else if v < 0x20 {
      out.push(' ')
    } else {
      out.push(c)
    }
  }
  String::from_array(out)
}