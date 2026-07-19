# Custom rules

Rules are JSON objects on a site. `custom_rules` can block or detect; `exceptions` let a request through.

```json
{
  "field": "path",
  "operator": "prefix",
  "value": "/.git",
  "action": "block",
  "sig": "sensitive-path"
}
```

## Fields

`uri`, `args`, `header`, `body`, `method`, `ip`, `country`, `location`, `path`, `query`, `fulluri`, `host`, `scheme`, `httpversion`, `useragent`, `referer`, `cookie`, `contenttype`

With `field: "header"`, name the header:

```json
{ "field": "header", "header_name": "X-Api-Key", "operator": "equals", "value": "", "action": "block" }
```

## Operators

`contains`, `equals`, `prefix`, `regex`, and the negated forms `not_contains`, `not_equals`, `not_prefix`, `not_regex`.

There are also structural operators that take no value: `detect_sqli` and `detect_xss` run the injection detector against that field.

## Actions

| Action | Effect |
|---|---|
| `block` | Reject (`block_status`, default 403). Only blocks in `protect` |
| `detect` | Log only, never blocks |
| `challenge` | Serve a proof-of-work page |
| `pass` / `allow` | Let it through, skipping remaining checks |
| `skip` | In exceptions: suppress one signal, keep the rest |

Set `sig` on every rule you care about. It becomes the label in logs, events and the `threatail_attacks_total` metric, which is the difference between "something blocked 4,000 requests" and knowing what.

`enabled: false` keeps a rule in the config without applying it.

## Composite conditions

Instead of `field`/`operator`/`value`, supply a `when` tree:

```json
{
  "when": {
    "op": "and",
    "conds": [
      { "field": "path", "operator": "prefix", "value": "/admin" },
      { "op": "not", "conds": [
        { "field": "ip", "operator": "prefix", "value": "10.0." }
      ]}
    ]
  },
  "action": "block",
  "sig": "admin-external"
}
```

`op` is `and`, `or` or `not`. Trees may nest. When `when` is present it replaces the flat condition.

## Exceptions

Exceptions run against the same fields and let traffic through that detection would otherwise stop.

```json
"exceptions": [
  { "field": "path", "operator": "prefix", "value": "/webhooks/stripe", "action": "pass" }
]
```

Prefer `skip` over `pass` where you can. `pass` disables *all* inspection for matching requests; `skip` suppresses one signal and leaves the rest active. A webhook endpoint that trips the SQLi signature because it carries SQL-ish JSON should skip that signature, not abandon inspection entirely.

Scope exceptions as tightly as the false positive requires. A broad `pass` on `/api/` is an unmonitored hole, and it will still be there in two years.

## Writing rules that hold up

**Test the bypass, not just the hit.** A rule blocking `sqlmap` in the user-agent stops exactly the attacker who did not change the default. Ask what the same request looks like with one character altered.

**Prefer structure over words.** `detect_sqli` reacts to the shape of SQL, so it survives `union/**/select` and encoding tricks. A `contains` rule on `union select` does not.

**Use `detect` first.** Add the rule, watch what it catches for a day, then switch to `block`. Rules written against imagined traffic tend to match real traffic in surprising ways.

**Watch order.** Exceptions are evaluated before blocking rules, and rate rules use longest-match. A broad exception can quietly neutralise a narrow rule you added later.

## Examples

Block a scanner user-agent:

```json
{ "field": "useragent", "operator": "contains", "value": "nikto", "action": "block", "sig": "scanner" }
```

Structural SQLi on the query string, scored rather than blocked:

```json
{ "field": "query", "operator": "detect_sqli", "value": "", "action": "detect", "sig": "sqli" }
```

Admin area, internal networks only:

```json
{
  "when": { "op": "and", "conds": [
    { "field": "path", "operator": "prefix", "value": "/admin" },
    { "field": "ip", "operator": "not_prefix", "value": "192.168." }
  ]},
  "action": "block", "sig": "admin-external"
}
```

Challenge instead of blocking, so humans can still get through:

```json
{ "field": "path", "operator": "prefix", "value": "/signup", "action": "challenge", "sig": "signup-pow" }
```
