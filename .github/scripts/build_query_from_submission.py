"""
Turn a website submission (repository_dispatch client_payload) into queries/<slug>.yml
in the same layout as the existing files, and write GitHub Actions outputs.

Expected client_payload shape (repository_dispatch allows max 10 top-level keys,
so everything is nested under one key):
  { "submission": { submission_id, name, description, cql, explanation,
                    tags, mitre_ids, log_sources, cs_required_modules,   <- comma separated
                    author, github_handle } }
"""
import json
import os
import re
import sys
from pathlib import Path

import yaml

raw = json.loads(os.environ["PAYLOAD"])
payload = raw.get("submission", raw)   # accept flat payload too
g = lambda k: (payload.get(k) or "").strip()


def split_list(value: str):
    # "Endpoint, Mail" -> ["Endpoint", "Mail"]; keeps "CSPM / ASPM / DSPM" intact
    return [v.strip() for v in re.split(r"\s*,\s*", value) if v.strip()]


def slugify(value: str) -> str:
    s = re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_")
    return s[:80] or "query"


def block(text: str) -> str:
    """Normalise newlines and indent for a YAML `|` block scalar."""
    text = text.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n")
    return "\n".join(("  " + line) if line.strip() else "" for line in text.split("\n"))


def yaml_list(items):
    return "\n".join(f"  - {json.dumps(i)}" if re.search(r"[:#/]", i) else f"  - {i}" for i in items)


name = g("name")
cql = g("cql")
if not name or not cql:
    sys.exit("Submission is missing 'name' or 'cql'")

slug = slugify(name)
out_dir = Path("queries")
out_path = out_dir / f"{slug}.yml"
if out_path.exists():
    # Avoid silently overwriting an existing query; make the PR reviewer decide.
    out_path = out_dir / f"{slug}_{g('submission_id')[-6:] or 'new'}.yml"
    slug = out_path.stem

def norm_mitre(value: str):
    """'t1003, 1003.001 ; TA0006' -> ['T1003', 'T1003.001', 'TA0006']. Drops junk."""
    out = []
    for m in re.split(r"[\s,;]+", value):
        m = m.strip().upper()
        if not m:
            continue
        if re.fullmatch(r"\d{4}(\.\d{3})?", m):      # missing 'T' prefix
            m = "T" + m
        if re.fullmatch(r"T\d{4}(\.\d{3})?|TA\d{4}", m):
            out.append(m)
    return list(dict.fromkeys(out))  # dedupe, keep order


mitre_ids = norm_mitre(g("mitre_ids"))
tags = split_list(g("tags"))
log_sources = split_list(g("log_sources"))
modules = split_list(g("cs_required_modules"))
author = g("author") or "Community contributor"
handle = g("github_handle").lstrip("@")

sections = [
    "# --- Query Metadata ---",
    "# Human-readable name for the query. Will be displayed as the title.",
    f"name: {json.dumps(name)}",
    "",
]
if mitre_ids:
    sections += ["# MITRE ATT&CK technique IDs", "mitre_ids:",
                 "\n".join(f"  - {json.dumps(m)}" for m in mitre_ids), ""]
if g("description"):
    sections += ["# Description of what the query does and its purpose.",
                 f"description: {json.dumps(g('description'))}", ""]
sections += ["# The author or team that created the query.", f"author: {json.dumps(author)}", ""]
if log_sources:
    sections += ["# The required log sources to run this query successfully in Next-Gen SIEM.",
                 "log_sources:", yaml_list(log_sources), ""]
if tags:
    sections += ["# Tags for filtering and categorization.", "tags:", yaml_list(tags), ""]
if modules:
    sections += ["cs_required_modules:", yaml_list(modules), ""]
sections += [
    "# --- Query Content ---",
    "# The actual CrowdStrike Query Language (CQL) code.",
    "cql: |",
    block(cql),
    "",
]
if g("explanation"):
    sections += ["# Explanation of the query. Uses markdown for formatting on the webpage.",
                 "explanation: |", block(g("explanation")), ""]

content = "\n".join(sections)

# Round-trip through PyYAML to make sure we produced valid YAML before writing.
yaml.safe_load(content)

out_dir.mkdir(exist_ok=True)
out_path.write_text(content, encoding="utf-8")
print(f"Wrote {out_path}")

# --- PR body ---
credit = f"[@{handle}](https://github.com/{handle})" if handle else author
pr_body = f"""Automated PR from a submission on [byteray.com/cql-hub-contribute](https://www.byteray.com/cql-hub-contribute).

**Query:** {name}
**Submitted by:** {credit}
**Tags:** {', '.join(tags) or '—'}
**MITRE:** {', '.join(mitre_ids) or '—'}
**Log sources:** {', '.join(log_sources) or '—'}
**Falcon modules:** {', '.join(modules) or '—'}
**Submission ID:** `{g('submission_id') or 'n/a'}`

Please review the query logic, test it, and merge or request changes.
"""
# Write OUTSIDE the checkout so create-pull-request does not commit it
pr_body_path = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "pr_body.md"
pr_body_path.write_text(pr_body, encoding="utf-8")

# git author: use GitHub noreply address so no email addresses are committed
if handle:
    git_author = f"{author} <{handle}@users.noreply.github.com>"
else:
    git_author = "CQL Hub Bot <cql-hub-bot@users.noreply.github.com>"

with open(os.environ["GITHUB_OUTPUT"], "a") as fh:
    fh.write(f"slug={slug}\n")
    fh.write(f"file={out_path}\n")
    fh.write(f"pr_body_file={pr_body_path}\n")
    fh.write(f"git_author={git_author}\n")
    # Escape newlines is not needed for a single-line name, but keep it safe
    fh.write(f"name={name.replace(chr(10), ' ')}\n")
