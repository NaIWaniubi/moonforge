// policy: small declarative rules, deterministic matching, JSON/SARIF results.

///| One policy rule. Empty kind/change/prefix means "any".
pub(all) struct PolicyRule {
  id : String
  kind : String
  change : String
  key_prefix : String
  severity : String
} derive(Debug)

///| A parsed policy document.
pub(all) struct Policy {
  rules : Array[PolicyRule]
} derive(Debug)

///| One rule violation.
pub(all) struct Violation {
  rule_id : String
  severity : String
  message : String
  change : String
  kind : String
  key : String
} derive(Debug)

///| Gate result. `passed` is true exactly when violations is empty.
pub(all) struct GateResult {
  violations : Array[Violation]
  passed : Bool
} derive(Debug)

fn string_field(obj : Map[String, Json], key : String, default : String) -> String {
  match obj.get(key) {
    Some(String(value)) => value
    _ => default
  }
}

fn parse_rule(value : Json) -> Result[PolicyRule, String] {
  match value {
    Object(obj) =>
      Ok({
        id: string_field(obj, "id", "rule"),
        kind: string_field(obj, "kind", ""),
        change: string_field(obj, "change", ""),
        key_prefix: string_field(obj, "key_prefix", ""),
        severity: string_field(obj, "severity", "warning"),
      })
    _ => Err("policy rule must be an object")
  }
}

///| Parse the documented policy JSON shape:
/// `{ "rules": [ { "id": "...", "kind": "import", "change": "added",
/// "key_prefix": "kernel32!", "severity": "high" } ] }`
pub fn parse_policy(text : String) -> Result[Policy, String] {
  let root = try @json.parse(text) catch { _ => return Err("invalid policy JSON") }
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
      Ok({ rules: rules })
    }
    _ => Err("policy root must be an object")
  }
}

fn matches(rule : PolicyRule, item : @diff.DiffItem) -> Bool {
  (rule.kind == "" || rule.kind == item.kind) &&
  (rule.change == "" || rule.change == item.change) &&
  (rule.key_prefix == "" || item.key.has_prefix(rule.key_prefix))
}

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

///| Evaluate every rule against every diff item. Results are sorted by rule id
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
  { violations: found, passed: found.length() == 0 }
}

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

///| Canonical JSON gate result.
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
