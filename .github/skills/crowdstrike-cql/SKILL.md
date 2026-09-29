---
name: crowdstrike-cql
description: "Write, explain, and troubleshoot CrowdStrike Falcon Next-Gen SIEM CQL. Use for CQL syntax, query structure, aggregation, query errors, or process, identity, network, endpoint-inventory, host-integrity, and data-movement hunts."
user-invocable: true
---

# CrowdStrike CQL

This core skill covers CQL syntax and query-writing practices. Focused query libraries contain complete CQL bodies for process, identity, network, endpoint inventory, host integrity, and data movement investigations.

CQL is a pipeline query language, not SQL. Event names, fields, functions, time-range handling, and request encoding depend on the Falcon query surface and tenant schema. This skill writes and explains queries; it does not execute them or make API calls.

## Query shape

Start with event or field filters, then add pipe-delimited stages. Do not use SQL `SELECT`, `WHERE`, or `GROUP BY` clauses.

```cql
#event_simpleName=ProcessRollup2
| in(field=FileName, values=["powershell.exe", "pwsh.exe"], ignoreCase=true)
| groupBy([FileName], function=count(as=executions))
```

`#event_simpleName=...` is a common event selector. `Field=*` selects events where that field is present. Use field names available in the target event schema.

## Membership filters

Use `in` for a set of alternatives, not SQL-style `field IN (...)`:

```cql
in(field=FileName, values=["powershell.exe", "pwsh.exe", "cmd.exe"], ignoreCase=true)
```

Keep `field` and `values` as named arguments when in doubt. Quote string values containing spaces or punctuation. For case-sensitive matching, omit `ignoreCase` or set it to `false` where supported.

## Regular expressions

Use `/pattern/` directly on a field; the trailing `i` enables case-insensitive matching:

```cql
CommandLine=/powershell(\.exe)?/i
```

Do not wrap CQL regexes in SQL `REGEXP`. Escape backslashes for CQL syntax, and apply JSON escaping separately when putting a query into a JSON request body.

## Aggregation

Use `groupBy` with fields in a list and the aggregate under `function=`:

```cql
| groupBy([ComputerName, UserName], function=count(as=event_count))
| sort(event_count, order=desc)
| head(20)
```

Some surfaces expose an unnamed count as `_count`. Use the aggregate's actual output field when sorting or filtering.

## Query-authoring workflow

1. Identify the investigation question, likely event family, indicator, platform, and time range. Ask one focused question or state assumptions if a missing detail materially changes the query.
2. Start with the narrowest supported event selector and indicator filter. Do not invent event fields or assume telemetry exists in the tenant.
3. Run a filter-only query first. Add parsing, joins, aggregation, and output formatting one stage at a time.
4. Select useful output fields and cap results with `limit` or `head` where appropriate.
5. Return CQL in a fenced `cql` block and state important event/field assumptions. For a catalog entry, return YAML with `name`, `log_sources`, and `cql: |`; keep metadata outside the CQL.
6. Never execute decoded commands from a query result. Treat results as investigative leads.

## HTTP 400 checks

- Replace SQL clauses and `IN (...)` with CQL field filters, `in(...)`, and pipeline stages.
- Check commas, brackets, parentheses, regex delimiters, and quoting.
- Put an aggregate under `function=`, for example `groupBy([HostName], function=count(as=hits))`.
- Separate CQL escaping from JSON request escaping.
- Reduce the query to its event selector, then add one filter or pipeline stage at a time. Confirm the query surface supports each field and function.
