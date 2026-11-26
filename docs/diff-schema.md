# MoonForge canonical fact and diff schema v1

## Fact set

```json
{
  "artifact_hash": "sha256 hex",
  "facts": [
    {
      "kind": "import | export | section | symbol | plist | wasm | xref",
      "key": "stable key within kind",
      "value": "normalized value",
      "location": {
        "section": ".text",
        "rva": 4096,
        "va": 4198400,
        "file_offset": 1024,
        "size": 16
      }
    }
  ]
}
```

Rules:

- `artifact_hash` is the SHA-256 of the input artifact.
- `kind` is a closed vocabulary owned by MoonForge adapters.
- `key` must be stable for the same logical fact across builds.
- `location` is required for byte-addressable facts; artifact-wide facts use zero fields.
- Facts are normalized and sorted by `kind`, then `key`; input order never affects output.

## Diff

```json
{
  "added": [DiffItem],
  "removed": [DiffItem],
  "changed": [DiffItem]
}
```

`DiffItem` contains `change`, `kind`, `key`, `old_value`, `new_value`, `old_location`, and `new_location`.

## Policy

```json
{
  "rules": [
    {
      "id": "no-new-import",
      "kind": "import",
      "change": "added",
      "key_prefix": "kernel32!",
      "severity": "high"
    }
  ]
}
```

Empty `kind`, `change`, or `key_prefix` means "any". A rule matches when all non-empty constraints match.

## Gate result and exit codes

```json
{
  "passed": false,
  "violations": [
    {
      "rule_id": "no-new-import",
      "severity": "high",
      "message": "no-new-import: added import kernel32!VirtualAlloc",
      "change": "added",
      "kind": "import",
      "key": "kernel32!VirtualAlloc"
    }
  ]
}
```

- `0`: gate passed.
- `1`: policy violation.
- `2`: input, parse, or tool error.
