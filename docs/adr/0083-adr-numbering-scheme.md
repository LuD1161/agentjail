# ADR 0083-adr-numbering-scheme: number first, three-word slug, checked in CI

**Status:** Accepted

## Context

ADR numbers collide, silently, and we only find out at merge time.

At the time of writing this repo had **three duplicate numbers** — and two of
them had been sitting there for weeks without anyone noticing:

| number | claimed by |
|---|---|
| 0016 | `rego-at-both-tiers` and `tier2-microsandbox-substrate` |
| 0048 | `ini-parser-for-aws-config` and `secrets-broker-key-store-excluded-from-agentjail-self-read` |
| 0075 | `bound-the-sighup-reload-rate` and `doctor-reports-whether-enforcement-ran` |

A third pair (0049: the netns/TUN ADR vs the cloud-metadata egress guard) was
resolved by hand, twice, when the tunnel branch merged — the netns ADR moved
0049 → 0075 → 0079 as main kept allocating underneath it.

The mechanism is mundane: two branches both take "next free number" from their
own view of `docs/adr/`, and nothing tells either one. Both files coexist —
different slugs, same number — so git never conflicts. Nothing fails.

The cost is not the filename. It is the **references**. Every ADR is cited from
prose and code as a bare number (`ADR 0034` appears 42 times, `ADR 0044` 41),
and once a number is contested, a bare citation stops identifying a document:

```go
// Cloud-metadata (IMDS) egress guard (P2/M2, ADR 0049).   <- the metadata ADR
// This file implements the unprivileged-userns TUN handoff (ADR 0049,  <- the OTHER 0049
```

Renumbering then means re-reading every reference to infer which ADR the author
meant. That is archaeology, and it is exactly the kind of ambiguity a decision
log exists to remove.

Two distinct problems hide in one symptom, and they need different fixes:

1. **Collision** — two ADRs taking one number. No naming convention prevents
   this; only a gate does.
2. **Ambiguity** — a reference that no longer resolves. This is what actually
   costs time, and a slug in the citation fixes it.

## Decision

### D1 — Filenames stay `NNNN-slug.md`, number first

The number leads because references and sort order depend on it, and because 78
existing ADRs already work this way. Numbers are allocated as next-free from
`main`.

### D2 — Slugs are at most three words, for new ADRs

`0083-adr-numbering-scheme.md`, not
`0083-how-we-number-adrs-and-avoid-collisions.md`. Short enough to cite inline
without eating the line. ADRs below 0080 are grandfathered: renaming 78 files
would break hundreds of links for no safety gain, so old long slugs stay.

### D3 — Cite `ADR NNNN-slug`, not `ADR NNNN`

New references name both:

```go
// See ADR 0082-doctor-attests-enforcement.
```

This is what makes a citation survive a renumber and stay greppable. It also
degrades gracefully: if a number does get contested, a slugged reference still
says which document it meant, so the fix is a rename rather than an
investigation. Existing bare references are not churned.

### D4 — CI fails on duplicate numbers

`scripts/adr-check.sh`, wired into `make adr-check` and the `ci` workflow, fails
on: a filename that is not `NNNN-slug.md`, any number claimed twice, and (from
0080 up) a slug longer than three words.

This is the load-bearing part. D1–D3 make collisions cheap to fix; only D4 stops
them reaching main. It is a ten-line shell script, and it would have caught all
three of the duplicates above at PR time.

## Consequences

- **The three existing duplicates are resolved**, by renumbering the
  less-referenced ADR of each pair and repointing its references by context:
  0016 → `0080-rego-both-tiers`, 0048 → `0081-aws-config-ini`,
  0075 → `0082-doctor-attests-enforcement`. The check cannot go green otherwise.
- **Mixed slug lengths, on purpose.** ADRs below 0080 keep their long slugs.
  Uniformity is not worth rewriting every link.
- **Numbers still race, they just cannot land.** Two branches can still pick
  0084; CI now tells the second one to move before it merges, which is a rename
  and a few citations rather than a post-merge hunt.
- **Long-lived branches should allocate late.** A branch that will sit for weeks
  is better off numbering its ADRs shortly before merge, or reserving a block, so
  it renumbers once instead of every time main advances — the netns ADR moved
  three times for exactly this reason.

## Related

- [ADR 0079-agent-netns-veth-vs-userns-tunfd](./0079-agent-netns-veth-vs-userns-tunfd.md)
  — the ADR that got renumbered twice; the case that prompted this.
- `scripts/adr-check.sh`, `make adr-check`, `.github/workflows/ci.yml`.
- [`AGENTS.md`](../../AGENTS.md) — the decision-log cadence this scheme serves.
