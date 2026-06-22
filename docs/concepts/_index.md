---
title: "Concepts"
linkTitle: "Concepts"
weight: 30
description: "Explanatory deep-dives into how go53 works."
---

# Concepts

Explanatory deep-dives into how go53 works under the hood:

- **[DNSSEC](/concepts/dnssec/)** — the signing model, refresh and jitter timing,
  query-time signing, NSEC/NSEC3 denial, parent signaling (DS/CDS/CDNSKEY), and
  the key lifecycle.
- **[Distributed Mode](/concepts/distributed-mode/)** — multi-node replication:
  architecture, Ed25519 signing, the frame protocol, vector clocks, and
  Merkle-tree integrity repair.
