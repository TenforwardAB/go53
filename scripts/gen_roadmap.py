#!/usr/bin/env python3
"""Generate docs/roadmap.md from the go53 Roadmap GitHub Project.

The narrative (release goals/themes, how the roadmap works) is static and lives
here; the per-release issue tables are pulled live from the Project so the page
never drifts from reality. Run via scripts/gen_roadmap.sh or the roadmap
workflow.

Requires `gh` authenticated with a token that can read the org Project
(read:project) — see .github/workflows/roadmap.yml.
"""

import datetime
import json
import os
import subprocess
import sys

OWNER = os.environ.get("ROADMAP_OWNER", "TenforwardAB")
PROJECT_NUMBER = os.environ.get("ROADMAP_PROJECT", "10")
OUT = os.environ.get("ROADMAP_OUT", "docs/roadmap.md")

# Ordered releases with their theme and goal (from the roadmap spec). Releases
# with no tickets yet still render so the plan is visible.
RELEASES = [
    ("0.79", "Operations", "Backup & Stability"),
    ("0.80", "Performance Foundation", "Remove obvious performance bottlenecks and establish benchmarks"),
    ("0.81", "Performance", "RRset Optimization"),
    ("0.82", "Performance", "Large Scale Zone Hosting"),
    ("0.83", "DNSSEC", "DNSSEC Production Hardening"),
    ("0.84", "Distributed", "Distributed Hardening"),
    ("0.85", "Operations", "Production Operations"),
    ("0.86", "Interoperability", "Modern DNS Ecosystem Support"),
    ("0.90", "Release", "Production Ready Community Edition"),
    ("1.0", "Release", "Recommended For Production"),
    ("Future", "Future", "Interesting ideas that are not currently roadmap priorities"),
]

# Status ordering for stable, readable tables.
STATUS_ORDER = {s: i for i, s in enumerate(
    ["In Progress", "Review", "Ready", "Blocked", "Backlog", "Done", ""])}


def fetch_items():
    out = subprocess.check_output(
        ["gh", "project", "item-list", PROJECT_NUMBER,
         "--owner", OWNER, "--limit", "200", "--format", "json"],
        text=True,
    )
    return json.loads(out).get("items", [])


def clean_title(t):
    t = (t or "").strip()
    if t.startswith("- "):
        t = t[2:]
    return t.replace("|", "\\|").strip()


def main():
    items = fetch_items()
    by_release = {}
    for it in items:
        c = it.get("content") or {}
        if not c.get("number"):
            continue  # skip draft items
        rel = it.get("release") or "Future"
        by_release.setdefault(rel, []).append(it)

    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = []
    lines.append("---")
    lines.append('title: "Roadmap"')
    lines.append("weight: 5")
    lines.append('description: "go53 release roadmap, auto-generated from the go53 Roadmap GitHub Project."')
    lines.append("---")
    lines.append("")
    lines.append("# go53 Roadmap")
    lines.append("")
    lines.append("go53 evolves toward a modern, secure, high-performance authoritative DNS")
    lines.append("server with first-class DNSSEC and distributed operation. The project")
    lines.append("prioritizes, in order: **reliability, RFC compliance, operational simplicity,")
    lines.append("performance, distributed resilience, and new features** — stability and")
    lines.append("maintainability over feature count.")
    lines.append("")
    lines.append("> This page is generated from the")
    lines.append(f"> [go53 Roadmap project](https://github.com/orgs/{OWNER}/projects/{PROJECT_NUMBER})")
    lines.append(f"> — last updated {now}. Status reflects the project board.")
    lines.append("")
    lines.append("## Releases")
    lines.append("")

    for rel, theme, goal in RELEASES:
        items_for = by_release.get(rel, [])
        heading = "Future / Unscheduled" if rel == "Future" else f"Release {rel}"
        lines.append(f"### {heading}")
        lines.append("")
        if rel not in ("Future",):
            lines.append(f"**Theme:** {theme} &nbsp;·&nbsp; **Goal:** {goal}")
            lines.append("")
        else:
            lines.append(f"{goal}.")
            lines.append("")
        if not items_for:
            lines.append("_No tickets assigned yet._")
            lines.append("")
            continue
        items_for.sort(key=lambda x: (STATUS_ORDER.get(x.get("status", ""), 99),
                                      (x.get("content") or {}).get("number", 0)))
        lines.append("| Issue | Title | Theme | Status |")
        lines.append("|-------|-------|-------|--------|")
        for it in items_for:
            c = it.get("content") or {}
            num = c.get("number")
            url = c.get("url")
            title = clean_title(c.get("title"))
            th = it.get("theme") or ""
            st = it.get("status") or "—"
            lines.append(f"| [#{num}]({url}) | {title} | {th} | {st} |")
        lines.append("")

    # Themes legend.
    lines.append("## Themes")
    lines.append("")
    lines.append("| Theme | Scope |")
    lines.append("|-------|-------|")
    for name, scope in [
        ("Performance", "QPS, latency, memory, allocation pressure, lock contention"),
        ("Operations", "Production operations: metrics, backup/restore, offline tooling, health"),
        ("DNSSEC", "Signing, validation interoperability, key rollover/management, metrics"),
        ("Distributed", "Replication, vector clocks, Merkle trees, cluster & split-brain handling"),
        ("Interoperability", "Compatibility with external DNS software, RFCs, industry standards"),
        ("Record Types", "New RR type support (TLSA, SSHFP, SVCB, HTTPS, …)"),
        ("Documentation", "Developer and operator documentation"),
        ("Security", "Security hardening and auditing"),
        ("Future", "Interesting ideas not currently prioritized"),
    ]:
        lines.append(f"| {name} | {scope} |")
    lines.append("")

    lines.append("## How this roadmap works")
    lines.append("")
    lines.append("- **Priority** — `P0 Critical` (must ship before the next release), "
                 "`P1 High` (on the current roadmap; 10–15 in Ready/In Progress at most), "
                 "`P2 Medium` (valid, not yet scheduled), `P3 Low` (nice-to-have).")
    lines.append("- **Sprints** — two weeks, targeting one major item plus a few small ones; "
                 "finishing work is favored over starting many in parallel.")
    lines.append("- **Future** items remain open but are intentionally not assigned to a release.")
    lines.append("")
    lines.append("The roadmap is successful when query latency drops, QPS rises, DNSSEC stays")
    lines.append("correct, distributed clusters stay stable, operators can monitor and recover")
    lines.append("easily, and external users adopt go53 in production.")
    lines.append("")

    content = "\n".join(lines)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        f.write(content)
    sys.stderr.write(f"wrote {OUT} ({len(items)} project items)\n")


if __name__ == "__main__":
    main()
