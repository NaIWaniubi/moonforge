// policy: small declarative rules, deterministic matching, JSON/SARIF results.

///|
/// One policy rule. Empty kind/change/prefix means "any".
pub(all) struct PolicyRule {
  id : String
  kind : String
  change : String
  key_prefix : String
  severity : String
} derive(Debug)

///|
/// A parsed policy document.
pub(all) struct Policy {
  rules : Array[PolicyRule]
} derive(Debug)

///|
/// One rule violation.
pub(all) struct Violation {
  rule_id : String
  severity : String
  message : String
  change : String
  kind : String
  key : String
} derive(Debug)

///|
/// Gate result. `passed` is true exactly when violations is empty.
pub(all) struct GateResult {
  violations : Array[Violation]
  passed : Bool
} derive(Debug)

///|
fn required_string(
  obj : Map[String, Json],
  key : String,
) -> Result[String, String] {
  match obj.get(key) {
    Some(String(value)) =>
      if value.length() > 0 {
        Ok(value)
      } else {
        Err("policy." + key + " must be a non-empty string")
      }
    _ => Err("policy." + key + " must be a string")
  }
}

///|
fn optional_string(
  obj : Map[String, Json],
  key : String,
  default : String,
) -> Result[String, String] {
  match obj.get(key) {
    None => Ok(default)
    Some(String(value)) => Ok(value)
    Some(_) => Err("policy." + key + " must be a string")
  }
}

///|
fn parse_rule(value : Json) -> Result[PolicyRule, String] {
  match value {
    Object(obj) => {
      let id = match required_string(obj, "id") {
        Ok(value) => value
        Err(error) => return Err(error)
      }
      let kind = match optional_string(obj, "kind", "") {
        Ok(value) => value
        Err(error) => return Err(error)
      }
      let change = match optional_string(obj, "change", "") {
        Ok(value) => value
        Err(error) => return Err(error)
      }
      let key_prefix = match optional_string(obj, "key_prefix", "") {
        Ok(value) => value
        Err(error) => return Err(error)
      }
      let severity = match optional_string(obj, "severity", "warning") {
        Ok(value) => value
        Err(error) => return Err(error)
      }
      if change != "" &&
        change != "added" &&
        change != "removed" &&
        change != "changed" {
        return Err("policy.change must be added, removed, changed, or empty")
      }
      if severity != "error" &&
        severity != "warning" &&
        severity != "note" &&
        severity != "none" &&
        severity != "high" &&
        severity != "medium" &&
        severity != "low" &&
        severity != "info" {
        return Err(
          "policy.severity must be error, warning, note, none, high, medium, low, or info",
        )
      }
      Ok({ id, kind, change, key_prefix, severity, })
    }
    _ => Err("policy rule must be an object")
  }
}

///|
/// Parse the documented policy JSON shape:
/// `{ "rules": [ { "id": "...", "kind": "import", "change": "added",
/// "key_prefix": "kernel32!", "severity": "high" } ] }`
pub fn parse_policy(text : String) -> Result[Policy, String] {
  let root = @json.parse(text, reject_duplicate_keys=true) catch {
    _ => return Err("invalid policy JSON")
  }
  match root {
    Object(obj) => {
      let rules_json = match obj.get("rules") {
        Some(Array(items)) => items
        _ => return Err("policy.rules must be an array")
      }
      let rules : Array[PolicyRule] = []
      for item in rules_json {
        let rule = match parse_rule(item) {
          Ok(value) => value
          Err(error) => return Err(error)
        }
        rules.push(rule)
      }
      Ok({ rules, })
    }
    _ => Err("policy root must be an object")
  }
}

///|
fn matches(rule : PolicyRule, item : @diff.DiffItem) -> Bool {
  (rule.kind == "" || rule.kind == item.kind) &&
  (rule.change == "" || rule.change == item.change) &&
  (rule.key_prefix == "" || item.key.has_prefix(rule.key_prefix))
}

///|
fn violation(rule : PolicyRule, item : @diff.DiffItem) -> Violation {
  {
    rule_id: rule.id,
    severity: rule.severity,
    message: rule.id + ": " + item.change + " " + item.kind + " " + item.key,
    change: item.change,
    kind: item.kind,
    key: item.key,
  }
}

///|
/// Evaluate every rule against every diff item. Results are sorted by rule id
/// then change/kind/key so output is byte-stable.
pub fn evaluate(report : @diff.DiffReport, policy : Policy) -> GateResult {
  let found : Array[Violation] = []
  for rule in policy.rules {
    for item in report.added {
      if matches(rule, item) {
        found.push(violation(rule, item))
      }
    }
    for item in report.removed {
      if matches(rule, item) {
        found.push(violation(rule, item))
      }
    }
    for item in report.changed {
      if matches(rule, item) {
        found.push(violation(rule, item))
      }
    }
  }
  found.sort_by(fn(a, b) {
    let ak = a.rule_id + "|" + a.change + "|" + a.kind + "|" + a.key
    let bk = b.rule_id + "|" + b.change + "|" + b.kind + "|" + b.key
    ak.compare(bk)
  })
  { violations: found, passed: found.length() == 0, }
}

///|
fn jviolation(v : Violation) -> Json {
  Json::object({
    "rule_id": Json::string(v.rule_id),
    "severity": Json::string(v.severity),
    "message": Json::string(v.message),
    "change": Json::string(v.change),
    "kind": Json::string(v.kind),
    "key": Json::string(v.key),
  })
}

///|
/// Canonical JSON gate result.
pub fn GateResult::to_json(self : GateResult) -> String {
  let items : Array[Json] = []
  for v in self.violations {
    items.push(jviolation(v))
  }
  Json::object({
    "passed": Json::boolean(self.passed),
    "violations": Json::array(items),
  }).stringify()
}
