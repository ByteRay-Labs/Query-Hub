#!/usr/bin/env python3
"""
Sync queries/*.yml from the Query-Hub repo into the Webflow "CQL Queries" collection.

Strategy: full reconciliation (desired state = repo, actual state = Webflow).
  - match files to items via the `source-file` field
  - create missing items, update changed ones, delete items whose file is gone
  - all writes go through the bulk *live* endpoints (create/update + publish in one step),
    so no site-wide publish and no sites:write scope is needed
  - `related-queries` (3 per item) is computed from shared MITRE IDs / tags / log sources / name tokens
"""
from __future__ import annotations

import argparse
import html
import json
import os
import re
import subprocess
import sys
import time
import unicodedata
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Iterable

import markdown
import requests
import yaml

API = "https://api.webflow.com/v2"
BATCH = 100
RELATED_COUNT = 3
MAX_DELETE_FRACTION = 0.20  # abort if a run would delete more than this share of the collection
PAGE_PREFIX = "/cql-hub/"

MD = markdown.Markdown(extensions=["fenced_code", "tables", "sane_lists"])


# ----------------------------------------------------------------------------- helpers
def log(msg: str) -> None:
    print(msg, flush=True)


def slugify(text: str) -> str:
    text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()
    text = re.sub(r"[^a-zA-Z0-9]+", "-", text).strip("-").lower()
    return text or "query"


def md_to_html(md: str | None) -> str:
    if not md or not md.strip():
        return ""
    MD.reset()
    return MD.convert(md).strip()


def html_text(s: str | None) -> str:
    """Tag-stripped, whitespace-collapsed text; Webflow rewrites rich-text HTML so we compare content only."""
    if not s:
        return ""
    s = re.sub(r"<[^>]+>", " ", s)
    s = html.unescape(s)
    return re.sub(r"\s+", " ", s).strip()


def join_list(v) -> str | None:
    if not v:
        return None
    if isinstance(v, str):
        v = [v]
    return ", ".join(str(x).strip() for x in v if str(x).strip()) or None


def norm_plain(v) -> str:
    if v is None:
        return ""
    if isinstance(v, str):
        return v.strip()
    return str(v)


def git_dates(path: Path) -> tuple[str, str]:
    """(created, updated) as YYYY-MM-DD from git author dates; falls back to today."""
    today = date.today().isoformat()
    try:
        first = subprocess.run(
            ["git", "log", "--follow", "--diff-filter=A", "--format=%aI", "--", str(path)],
            capture_output=True, text=True, check=True,
        ).stdout.strip().splitlines()
        last = subprocess.run(
            ["git", "log", "-1", "--format=%aI", "--", str(path)],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    except Exception:
        return today, today
    created = first[-1][:10] if first else today
    updated = last[:10] if last else today
    return created, updated


# ----------------------------------------------------------------------------- data model
@dataclass
class Query:
    source_file: str
    name: str
    cql: str
    description: str | None
    explanation_md: str | None
    author: str | None
    mitre_ids: list[str]
    tags: list[str]
    log_sources: list[str]
    modules: list[str]
    created: str
    updated: str
    slug: str = ""
    item_id: str | None = None          # existing Webflow item id, if any
    related: list[str] = field(default_factory=list)  # source_files of related queries

    @classmethod
    def from_file(cls, path: Path) -> "Query":
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict) or not data.get("name") or not data.get("cql"):
            raise ValueError(f"{path}: missing required name/cql")
        created, updated = git_dates(path)

        def lst(k):
            v = data.get(k)
            if v is None:
                return []
            if isinstance(v, str):
                return [v]
            return [str(x) for x in v]

        return cls(
            source_file=path.name,
            name=str(data["name"]).strip(),
            cql=str(data["cql"]).rstrip("\n"),
            description=(str(data["description"]).strip() if data.get("description") else None),
            explanation_md=data.get("explanation"),
            author=(str(data["author"]).strip() if data.get("author") else None),
            mitre_ids=lst("mitre_ids"),
            tags=lst("tags"),
            log_sources=lst("log_sources"),
            modules=lst("cs_required_modules"),
            created=created,
            updated=updated,
        )

    def field_data(self, id_by_file: dict[str, str]) -> dict:
        page = PAGE_PREFIX + self.slug
        return {
            "name": self.name[:256],
            "slug": self.slug,
            "description": self.description,
            "cql-code": self.cql,
            "explanation": md_to_html(self.explanation_md),
            "mitre-ids": join_list(self.mitre_ids),
            "tags": join_list(self.tags),
            "log-sources": join_list(self.log_sources),
            "required-modules": join_list(self.modules),
            "author": self.author,
            "source-file": self.source_file,
            "created": self.created,
            "updated": self.updated,
            "page-url": page,
            "page-link": page,
            "related-queries": [id_by_file[f] for f in self.related if f in id_by_file],
        }


def load_queries(qdir: Path) -> list[Query]:
    files = sorted(list(qdir.glob("*.yml")) + list(qdir.glob("*.yaml")))
    out, errors = [], []
    for f in files:
        try:
            out.append(Query.from_file(f))
        except Exception as e:  # validate.yml should have caught this, but never sync garbage
            errors.append(str(e))
    if errors:
        for e in errors:
            log(f"✗ {e}")
        raise SystemExit(f"{len(errors)} query file(s) failed to parse – aborting sync")
    return out


# ----------------------------------------------------------------------------- related queries
def _tokens(name: str) -> set[str]:
    stop = {"the", "a", "an", "of", "in", "on", "for", "to", "and", "or", "via", "with", "by",
            "from", "query", "queries", "detection", "detect", "detects", "hunting", "hunt",
            "monitoring", "monitor", "activity", "events", "event", "all", "using", "suspicious"}
    return {t for t in re.findall(r"[a-z0-9]+", name.lower()) if len(t) > 2 and t not in stop}


def compute_related(queries: list[Query]) -> None:
    toks = {q.source_file: _tokens(q.name) for q in queries}
    for q in queries:
        scored = []
        for o in queries:
            if o is q:
                continue
            s = 0.0
            mine, theirs = set(q.mitre_ids), set(o.mitre_ids)
            s += 4 * len(mine & theirs)
            s += 1.5 * len({m.split(".")[0] for m in mine} & {m.split(".")[0] for m in theirs})
            s += 1.0 * len(set(q.log_sources) & set(o.log_sources))
            s += 0.5 * len(set(q.modules) & set(o.modules))
            s += 0.5 * len(set(q.tags) & set(o.tags))
            shared = toks[q.source_file] & toks[o.source_file]
            s += 2.0 * len(shared)
            if q.author and q.author == o.author:
                s += 0.25
            scored.append((s, o.name.lower(), o.source_file))
        scored.sort(key=lambda t: (-t[0], t[1]))
        q.related = [sf for _, _, sf in scored[:RELATED_COUNT]]


# ----------------------------------------------------------------------------- webflow client
class Webflow:
    def __init__(self, token: str, collection_id: str, dry_run: bool):
        self.s = requests.Session()
        self.s.headers.update({"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                               "accept": "application/json"})
        self.cid = collection_id
        self.dry_run = dry_run
        self.calls = 0

    def _req(self, method: str, path: str, **kw) -> dict:
        url = f"{API}{path}"
        for attempt in range(8):
            self.calls += 1
            r = self.s.request(method, url, timeout=60, **kw)
            if r.status_code == 429:
                wait = int(r.headers.get("Retry-After", "0") or 0) or min(60, 2 ** attempt)
                log(f"  rate limited, sleeping {wait}s")
                time.sleep(wait)
                continue
            if r.status_code >= 500 and attempt < 3:
                time.sleep(2 ** attempt)
                continue
            if not r.ok:
                raise RuntimeError(f"{method} {path} -> {r.status_code}: {r.text[:1000]}")
            return r.json() if r.text else {}
        raise RuntimeError(f"{method} {path}: gave up after retries")

    def list_items(self) -> list[dict]:
        items, offset = [], 0
        while True:
            page = self._req("GET", f"/collections/{self.cid}/items", params={"limit": 100, "offset": offset})
            items.extend(page.get("items", []))
            total = page.get("pagination", {}).get("total", len(items))
            offset += 100
            if offset >= total or not page.get("items"):
                break
        return items

    def _write(self, method: str, path: str, body: dict, label: str) -> dict:
        if self.dry_run:
            return {}
        out = self._req(method, path, data=json.dumps(body))
        time.sleep(1.0)  # stay well under 60 req/min on writes
        return out

    def create_live(self, field_datas: list[dict]) -> list[dict]:
        created = []
        for i in range(0, len(field_datas), BATCH):
            chunk = field_datas[i:i + BATCH]
            body = {"items": [{"isArchived": False, "isDraft": False, "fieldData": fd} for fd in chunk]}
            res = self._write("POST", f"/collections/{self.cid}/items/live", body, "create")
            created.extend(res.get("items", []))
        return created

    def update_live(self, updates: list[tuple[str, dict]]) -> None:
        for i in range(0, len(updates), BATCH):
            chunk = updates[i:i + BATCH]
            body = {"items": [{"id": iid, "isArchived": False, "isDraft": False, "fieldData": fd} for iid, fd in chunk]}
            self._write("PATCH", f"/collections/{self.cid}/items/live", body, "update")

    def delete(self, ids: list[str]) -> None:
        for i in range(0, len(ids), BATCH):
            chunk = [{"id": x} for x in ids[i:i + BATCH]]
            # unpublish from live site, then remove the staged item so it's really gone
            self._write("DELETE", f"/collections/{self.cid}/items/live", {"items": chunk}, "unpublish")
            self._write("DELETE", f"/collections/{self.cid}/items", {"items": chunk}, "delete")


# ----------------------------------------------------------------------------- reconciliation
def diff_fields(desired: dict, existing: dict) -> list[str]:
    """Return list of field slugs that differ (normalised so Webflow's rewrites don't cause churn)."""
    changed = []
    for k, v in desired.items():
        e = existing.get(k)
        if k == "explanation":
            if html_text(v) != html_text(e):
                changed.append(k)
        elif k == "related-queries":
            if list(v or []) != list(e or []):
                changed.append(k)
        else:
            if norm_plain(v) != norm_plain(e):
                changed.append(k)
    return changed


def assign_slugs(queries: list[Query], existing_by_file: dict[str, dict], existing_items: list[dict]) -> None:
    """Keep existing slugs (live URLs!), slugify the rest, guarantee uniqueness."""
    taken: dict[str, str] = {}  # slug -> source_file
    for q in queries:
        ex = existing_by_file.get(q.source_file)
        if ex and ex["fieldData"].get("slug"):
            q.slug = ex["fieldData"]["slug"]
            taken[q.slug] = q.source_file
    # slugs held by items we won't touch (hand-made items without source-file) must not be reused
    reserved = {it["fieldData"].get("slug") for it in existing_items if not it["fieldData"].get("source-file")}
    for q in queries:
        if q.slug:
            continue
        base = slugify(q.name)
        cand, n = base, 2
        while cand in taken or cand in reserved:
            cand, n = f"{base}-{n}", n + 1
        q.slug = cand
        taken[cand] = q.source_file


def run(args) -> int:
    token = os.environ.get("WEBFLOW_API_TOKEN")
    if not token:
        log("WEBFLOW_API_TOKEN not set")
        return 2
    cid = os.environ.get("WEBFLOW_COLLECTION_ID")
    if not cid:
        log("WEBFLOW_COLLECTION_ID not set")
        return 2
    qdir = Path(os.environ.get("QUERIES_DIR", "queries"))

    wf = Webflow(token, cid, dry_run=args.dry_run)
    queries = load_queries(qdir)
    log(f"Loaded {len(queries)} queries from {qdir}/")

    existing = wf.list_items()
    log(f"Fetched {len(existing)} items from Webflow")
    existing_by_file: dict[str, dict] = {}
    dupes = defaultdict(list)
    for it in existing:
        sf = (it["fieldData"].get("source-file") or "").strip()
        if sf:
            dupes[sf].append(it)
            existing_by_file.setdefault(sf, it)
    for sf, its in dupes.items():
        if len(its) > 1:
            log(f"⚠ {sf} is present {len(its)}× in Webflow (ids {[i['id'] for i in its]}) – using the first, "
                f"please clean up the rest manually")

    assign_slugs(queries, existing_by_file, existing)
    for q in queries:
        if q.source_file in existing_by_file:
            q.item_id = existing_by_file[q.source_file]["id"]
    compute_related(queries)

    # ---- deletes: items that carry a source-file we no longer have
    repo_files = {q.source_file for q in queries}
    to_delete = [it for sf, it in existing_by_file.items() if sf not in repo_files]
    # duplicates beyond the first are intentionally NOT auto-deleted (human decision)
    orphans = [it for it in existing if not (it["fieldData"].get("source-file") or "").strip()]
    if orphans:
        log(f"ℹ {len(orphans)} item(s) without source-file are left untouched: "
            f"{[o['fieldData'].get('slug') for o in orphans]}")

    # ---- renames: a new file whose slug is held by a to-be-deleted item adopts that item
    #      (keeps the public URL and the item id instead of delete + create)
    by_slug_deletable = {it["fieldData"].get("slug"): it for it in to_delete}
    adopted = []
    for q in queries:
        if not q.item_id and q.slug in by_slug_deletable:
            it = by_slug_deletable.pop(q.slug)
            q.item_id = it["id"]
            existing_by_file[q.source_file] = it  # so it goes through the normal diff/update path
            adopted.append((it["fieldData"].get("source-file"), q.source_file))
    if adopted:
        to_delete = [it for it in to_delete if it["fieldData"].get("slug") in by_slug_deletable]
        for old, new in adopted:
            log(f"  ↻ rename  {old}  ->  {new}  (item kept, URL unchanged)")

    # ---- creates (pass 1, without related-queries because new ids don't exist yet)
    id_by_file = {q.source_file: q.item_id for q in queries if q.item_id}
    to_create = [q for q in queries if not q.item_id]

    # ---- plan output
    log("")
    log(f"Plan: create {len(to_create)}, delete {len(to_delete)}, "
        f"then check {len(queries) - len(to_create)} existing items for changes")
    for q in to_create:
        log(f"  + create  {q.source_file}  ->  /cql-hub/{q.slug}")
    for it in to_delete:
        log(f"  - delete  {it['fieldData'].get('source-file')}  (/cql-hub/{it['fieldData'].get('slug')})")

    if to_delete and not args.no_delete and existing:
        frac = len(to_delete) / len(existing)
        if frac > MAX_DELETE_FRACTION and not args.force:
            log(f"\n✗ Refusing to delete {len(to_delete)}/{len(existing)} items ({frac:.0%}) – "
                f"that exceeds the {MAX_DELETE_FRACTION:.0%} safety limit. Re-run with --force if intended.")
            return 3

    if to_create:
        fds = []
        for q in to_create:
            fd = q.field_data(id_by_file)
            fd["related-queries"] = []
            fds.append(fd)
        created = wf.create_live(fds)
        if not args.dry_run:
            by_sf = {c["fieldData"].get("source-file"): c["id"] for c in created}
            for q in to_create:
                q.item_id = by_sf.get(q.source_file)
                if not q.item_id:
                    log(f"⚠ create response missing {q.source_file}")
            id_by_file = {q.source_file: q.item_id for q in queries if q.item_id}
        log(f"Created {len(to_create)} item(s)")

    # ---- updates (pass 2: full field comparison incl. related-queries)
    updates: list[tuple[str, dict]] = []
    change_log: list[str] = []
    for q in queries:
        if not q.item_id and args.dry_run and q in to_create:
            # would get its related-queries in the second pass
            change_log.append(f"  ~ update  {q.source_file}  [related-queries] (after create)")
            continue
        if not q.item_id:
            continue
        desired = q.field_data(id_by_file)
        ex = existing_by_file.get(q.source_file)
        if ex is None:  # just created -> only related-queries missing
            if desired["related-queries"]:
                updates.append((q.item_id, {"related-queries": desired["related-queries"]}))
                change_log.append(f"  ~ update  {q.source_file}  [related-queries] (after create)")
            continue
        changed = diff_fields(desired, ex["fieldData"])
        if changed:
            updates.append((q.item_id, desired))
            change_log.append(f"  ~ update  {q.source_file}  [{', '.join(changed)}]")
    for line in change_log:
        log(line)
    if updates:
        wf.update_live(updates)
    log(f"Updated {len(updates)} item(s)")

    # ---- deletes last (so nothing references them anymore)
    if to_delete and not args.no_delete:
        wf.delete([it["id"] for it in to_delete])
        log(f"Deleted {len(to_delete)} item(s)")
    elif to_delete:
        log(f"Skipped {len(to_delete)} deletion(s) (--no-delete)")

    unchanged = len(queries) - len(to_create) - sum(1 for u in updates if u[1].get("name"))
    summary = (f"{'DRY RUN – ' if args.dry_run else ''}created {len(to_create)}, updated {len(updates)}, "
               f"deleted {0 if args.no_delete else len(to_delete)}, unchanged {max(unchanged, 0)}, "
               f"API calls {wf.calls}")
    log(f"\n{summary}")
    step = os.environ.get("GITHUB_STEP_SUMMARY")
    if step:
        with open(step, "a", encoding="utf-8") as fh:
            fh.write(f"### Webflow sync\n{summary}\n\n")
            for line in [f"  + create  {q.source_file}" for q in to_create] + change_log + \
                        [f"  - delete  {it['fieldData'].get('source-file')}" for it in to_delete]:
                fh.write(f"- `{line.strip()}`\n")
    return 0


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dry-run", action="store_true", help="print the plan, change nothing")
    p.add_argument("--no-delete", action="store_true", help="never delete items from Webflow")
    p.add_argument("--force", action="store_true", help="bypass the mass-deletion safety limit")
    sys.exit(run(p.parse_args()))


if __name__ == "__main__":
    main()