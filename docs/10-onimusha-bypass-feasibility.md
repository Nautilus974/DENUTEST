# Phase 6 — Onimusha: Denuvo Bypass Feasibility (evidence-based assessment)

**What this is.** A technical *feasibility assessment* of circumventing Denuvo on
*Onimusha: Way of the Sword*, graded strictly by the evidence actually available.
**What this is not.** It is not a bypass procedure, not circumvention tooling, and
not an analysis of the game binary (none is present). No step-by-step method is
given. Every claim below is tagged with a **source** (secondary web report) or a
**reproducible lab result** (our own code). Nothing untested is presented as a
discovery; the game was not tested.

Study date 2026-10-14. Lab base commit `04237b3`. Every lab figure is from
`ctest` on this repo (10/10 suites, GCC+Clang, Debug+Release, ASan+UBSan clean).

---

## 0. Explicit verdict (up front)

| Question | Verdict | Basis |
|----------|---------|-------|
| Is the **general** hypervisor/Ring-1 *environment-deception* class a real way to bypass Denuvo on **some** titles? | **Feasibility reported and well-corroborated** (secondary sources), **not independently verified here** | multiple independent outlets; §2 |
| Was **Onimusha specifically** bypassed? | **Insufficient evidence** — a single, uncorroborated, technically-undetailed claim | §1, §3 |
| Has Onimusha's Denuvo been **fully cracked** (core removed, no preconditions)? | **No evidence found** | §1, §3 |
| Did *this study* demonstrate a working bypass of Onimusha? | **No** — no binary, no test, no proof | §4, §6 |

One-line conclusion: **For the general technique class, feasibility is supported
by converging secondary reports; for Onimusha specifically, the evidence is
insufficient to conclude a bypass was achieved, and there is no evidence of a
full crack.** This study proves nothing about the game directly; it reproduces
only the *general* security properties that make the reported class plausible
(§5).

---

## 1. Public reports on Onimusha specifically — and confirmation search

- **Denuvo is present on the PC build** (pre-launch, multiple outlets). Capcom
  reported to use Denuvo Anti-Tamper; first-run online setup noted.
  [DSOGaming], [GamingOnLinux].
- **The Onimusha bypass claim is single-source.** Only **iXBT** (2026-09-04)
  reports a release-day bypass "using a hypervisor method," and the same article
  states **no full Denuvo crack was presented** and names a group ("voices38").
  [ixbt.games].
- **Independent confirmation: not found.** Repeated searches surfaced **no second
  outlet, researcher, or technical write-up** confirming an Onimusha bypass, and
  iXBT gives **no verifiable technical detail**. Notably, the better-sourced
  round-ups of 2026 hypervisor bypasses (below) name *other* titles — **Onimusha
  is not among them**.
- **"voices38" ≠ Onimusha evidence.** That group is reported doing *full* Denuvo
  removal on **Resident Evil Requiem** and **Doom: The Dark Ages** — different
  games; this does not establish anything about Onimusha. [TorrentFreak].

→ Onimusha-specific status: **one unverified claim of a partial (environment)
bypass; no corroboration; no full crack reported.**

## 2. The general technique class — this is the well-corroborated part

Multiple **independent** secondary outlets describe a 2026 class of Denuvo
bypasses operating *beneath* the OS, consistent with each other:
- They run a hypervisor at **Ring-1** (under Windows) that **deceives the
  protection's environment checks** rather than patching game code — reportedly
  intercepting CPUID, forging memory structures, and manipulating timing so the
  checks "see" a legitimate machine. [TorrentFreak], [Korben], [TweakTown].
- **Preconditions and cost (reported):** requires **disabling Windows protections
  (VBS, HVCI, driver-signature enforcement)**, which **exposes the machine to
  rootkits/malware**; hardware-dependent (AMD reportedly more stable than Intel).
  [Korben], [ixbt.games].
- **Scope (reported day-zero titles):** Crimson Desert, Life is Strange: Reunion,
  Assassin's Creed Shadows, Resident Evil Requiem — **not Onimusha** in these
  sources. [TorrentFreak], [Korben].
- **Vendor response:** Irdeto (Denuvo) says countermeasures are in progress.
  [TorrentFreak], [TweakTown].
- **Caveat:** all of the above is **secondary press and community trackers
  (e.g. CrackWatch)**, not primary technical/academic analysis; a Habr "technical"
  piece carries an unverifiable disclaimer and is **not relied upon**. [TechSpot].

> This report deliberately does **not** reproduce or detail the method. The
> description above is limited to characterizing *what is publicly claimed*, its
> preconditions, and its cost.

## 3. Mechanisms vs. demonstrated vulnerabilities vs. hypotheses

| Item | Classification | Evidence |
|------|----------------|----------|
| Anti-tamper **environment/anti-debug observation** (CPUID, timing, memory checks) is the mechanism the reported class targets | **Mechanism (named in reports)** | [TorrentFreak], [Korben] |
| Hypervisor/Ring-1 **environment deception** can yield day-zero playability for **some** Denuvo titles | **Demonstrated in the wild per converging secondary reports** (not primary-verified here) | §2 |
| The same class **specifically** defeated **Onimusha** | **Unverified hypothesis** (single source, no detail) | §1 |
| A **full crack** (licensing/core removed) of Onimusha exists | **No evidence** | §1 |
| The internal structure of Onimusha's Denuvo build (version, checks, VM) | **Unknown / unverifiable here** | — |

## 4. Security properties relevant to feasibility, and what a real conclusion needs

Bypass feasibility turns on which of two gate types protects the functionality
(modeled and reproduced in §5):
- **Environment gates** (anti-debug/anti-VM) decide from what the environment
  *reports*. They are **bypassable by a more-privileged layer** that controls the
  report — this is exactly the reported Ring-1 class — and they **false-positive**
  on legitimate VMs. Low assurance as a trust boundary.
- **Entitlement/core gates** that require a **secret the attacker lacks**
  (server/hardware-bound keyed check) are **not** defeated by environment control;
  defeating them needs the secret or a break of the primitive. This is the general
  reason a reported "bypass" (environment) is **not** the same as a "full crack"
  (core).

**To establish an Onimusha-specific feasibility conclusion one would need** (all
absent here): the lawfully-obtained binary + exact build; a primary technical
PoC or independent corroboration of the iXBT claim; evidence of *which* gate type
actually gates Onimusha's functionality and whether the reported bypass yields a
*fully playable, offline* game; and authorization to analyze. Without these, an
Onimusha-specific verdict beyond "insufficient evidence" is not warranted.

## 5. Reproducible lab results (general properties, on OUR code — not the game)

New model `src/protection_model.*` + `tests/test_protection_model.cpp`. Observed:
```
test_protection_model:
  ok: G1: honest 'debugger+VM' report is denied
  ok: G1: honest 'VM present' report is denied (also a FALSE POSITIVE for legit VMs)
  ok: G1: a report of 'clean' is admitted — whoever controls the report controls the gate
  ok: G2: correct token (holder of the secret) passes
  ok: G2: 200k forged tokens without the secret: 0 pass
  ok: G2: passing the environment gate does NOT pass the entitlement gate (bypass != full crack)
```
Plus Phase-5 properties still passing (`test_security_properties`): in-process
integrity reduces to key secrecy; env verdict is a pure function of the reported
CPUID bit.

**Interpretation (strictly general):** G1 reproduces *why* an environment-level
bypass can succeed — the gate trusts an untrusted report. G2 reproduces *why*
"bypass ≠ full crack" — a secret-dependent core resists environment control.
These are properties of **our** abstract model; they are **consistent with** the
public descriptions in §2 but are **not** evidence about Onimusha and are **not**
transposed to it.

## 6. Missing information blocking an Onimusha-specific conclusion
- No game binary, no Denuvo source, no exact build number.
- No primary technical write-up or PoC; `WebFetch` to the two bypass-claim hosts
  failed (DNS blocked), so only **search-engine summaries** could be read — a real
  verification limit.
- No independent corroboration of the single Onimusha claim.
- No knowledge of which gate protects the game's functionality, nor whether the
  reported bypass produces a fully-playable result.
- No authorization to analyze the game (and analysis is out of scope regardless).

## 7. Conclusion (graded)
- **General hypervisor/Ring-1 environment-deception class vs. Denuvo:**
  **feasibility supported by converging secondary reporting**, with heavy
  preconditions (disabling VBS/HVCI/DSE, system-exposure, hardware variance) and
  **no primary verification in this study**.
- **Onimusha: Way of the Sword specifically:** **insufficient evidence** — one
  uncorroborated, technically-undetailed claim of a *partial* bypass; **no full
  crack reported**; Onimusha absent from better-sourced lists.
- **This study:** demonstrated **no** bypass of the game and makes **no** such
  claim; it reproduced only the general properties (§5) that make the reported
  class plausible and explain "bypass ≠ full crack."

The honest state of knowledge: *the technique class is real and widely reported;
its specific success on Onimusha is unconfirmed; a full crack is unevidenced; and
nothing here was shown on the game itself.*

---

## Sources (secondary; data for "what is publicly reported", not verified fact)
- [DSOGaming — Onimusha will have Denuvo](https://www.dsogaming.com/news/onimusha-way-of-the-sword-will-have-denuvo-gets-pc-demo-pc-requirements/)
- [GamingOnLinux — Sep 4 release, Denuvo/online setup](https://www.gamingonlinux.com/2026/07/onimusha-way-of-the-sword-releases-earlier-on-september-4-steam-deck-steamos-playable/)
- [ixbt.games — "Denuvo bypassed in Onimusha on release day" (single-source claim)](https://ixbt.games/en/news/2026/09/04/denuvo-obosli-v-onimusha-way-of-the-sword-v-den-reliza.html)
- [TorrentFreak — hypervisor bypasses, title list, Irdeto countermeasure](https://torrentfreak.com/game-pirates-beat-denuvo-with-hypervisor-bypasses-irdeto-promises-countermeasure/)
- [TweakTown — hypervisor-based day-zero bypasses + countermeasure](https://www.tweaktown.com/news/110787/hypervisor-based-bypasses-defeat-denuvo-with-day-zero-cracks-but-a-countermeasure-is-already-in-the-works/index.html)
- [TechSpot — CrackWatch community tracker / broad bypassability](https://www.techspot.com/news/112202-denuvo-may-have-reached-end-every-protected-pc.html)
- [Korben (EN) — EfiGuard/hypervisor technique, VBS/HVCI, titles](https://korben.info/en/denuvo-falls-in-hours-hypervisor-bypass.html)
- [GamersNexus — Denuvo VM performance (general)](https://gamersnexus.net/industry/2555-denuvo-drm-loopholes)

*All rows are secondary news/community content, summarized as reported claims and
not independently verified. A Habr piece appearing in results is treated as
lowest-trust and not relied upon.*
