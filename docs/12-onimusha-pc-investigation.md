# Phase 8 — Targeted Investigation: Denuvo in Onimusha: Way of the Sword (PC)

**Scope.** Only *Onimusha: Way of the Sword*, PC version. No code, no generic lab
work, no re-run of the CPUID/clock experiments. Pure source investigation.
**Constraints honored.** The game binary was **not** examined (it is not
available here); no bypass method is reproduced; a how-to video that surfaced in
results was **deliberately not opened or used**. Investigation date 2026-10-14.
All sources are secondary (news/trackers); none is a primary technical analysis.

---

## 1. The "day-one bypass" claim — tracing the source

- **Earliest news item found:** iXBT, dated **2026-09-04** (the PC launch day),
  "Denuvo bypassed in Onimusha on release day." It states the bypass used a
  **hypervisor method** and that the group it names **had not presented a full
  Denuvo crack** — i.e. partial. [ixbt.games].
- **Corroboration (same claim, other outlets):** VGTimes repeats it (hypervisor
  workaround soon after release; "a full Denuvo crack has not been presented
  yet"). [VGTimes]. A CrackWatch-style tracker lists it as **"bypassed with
  Hypervisor by DENUVOWO after 1 day."** [isitcracked/CrackWatch].
- **Primary source:** **not found.** No scene release note / NFO, no security or
  reverse-engineering write-up, and no technical analysis was located. A YouTube
  "DenuvOwO hypervisor bypass setup tutorial (Onimusha)" exists; it is a how-to
  video, **not** an analysis, and it was **not opened or used** in this study.
- **Net:** the claim is now **multi-source** (better than the single-source
  picture in `docs/10`), but every source is **secondary news/tracker**, and the
  **underlying artifact is a scene-group hypervisor tool, not a documented
  vulnerability.**

## 2. Does the claim really concern Onimusha — partial, or another game?

- **It does concern Onimusha**, but as **one instance of the generic 2026
  hypervisor bypass** (attributed to **DENUVOWO** via the "Hypervisor" method),
  the same game-agnostic technique reported against many titles that season
  (e.g. Crimson Desert, Resident Evil Requiem). [TechSpot].
- **It is explicitly partial.** All sources agree it is an **environment-level
  bypass**, **not a full crack**; the separate full-removal group (**voices38**)
  is reported to **not** have released a full Onimusha crack. [ixbt.games],
  [VGTimes].
- **Mechanism is not game-specific.** The technique deceives the *environment*
  the protection observes (hypervisor beneath the OS); it is not an exploit of
  anything unique to Onimusha's code, and it requires the user to disable Windows
  security features. [VGTimes], [TechSpot].

## 3. PC-specific technical facts (confirmed vs. supposition)

**Reasonably confirmed (multiple/consistent sources):**
- PC version is protected with **Denuvo Anti-Tamper**. [DSOGaming], [allkeyshop].
- **Machine-activation limit: 5 different PCs within one day** (Steam listing);
  this limits activations, not ordinary relaunches. [ConsolePulse].
- **First-run internet** required for setup. [GamingOnLinux].
- Activation via **Steam**; released **2026-09-04** in the unified launch.
  [GamingOnLinux].

**Reported by a single source — treat as to-verify:**
- The PC build reportedly layered **Steam DRM + VMProtect + Denuvo + Capcom's own
  anti-piracy**, not Denuvo alone. [VGTimes]. (Plausible and notable, but
  single-source; confirm against the store/primary material.)

**Date discrepancy (noted honestly):** some pre-change PC pages cite a **Sep 25**
PC date; the unified launch moved to **Sep 4**. The bypass report and tracker
both key off **Sep 4 / "after 1 day."** [DSOGaming] vs [GamingOnLinux].

**Supposition / unknown:** the specific Denuvo version/build, its check cadence,
VM-handler set, or any internal configuration. No source establishes these.

## 4. Was an Onimusha-SPECIFIC vulnerability publicly demonstrated?

**No — not on the available evidence.**
- What is reported is the application of a **game-agnostic** hypervisor
  environment-deception technique that would affect essentially any current
  Denuvo title, **not** a weakness specific to Onimusha's protection.
- **No technical write-up, PoC, or reverse-engineering analysis** tied to
  Onimusha was found — only news, a tracker entry, and a how-to video (unused).
- The reported result is a **partial, environment-level bypass requiring the user
  to weaken their own system**, with **no full crack** and **no demonstrated
  game-specific flaw**.

### Precisely what is missing to confirm a game-specific weakness
1. A **primary artifact**: a scene release note/NFO, a security/RE write-up, or a
   reproducible PoC attributable to this title (none found).
2. The **game binary** + exact Denuvo build (not available; not examined here).
3. Evidence that any flaw is **specific to Onimusha** rather than the generic
   environment-deception class (nothing found distinguishes it).
4. **Independent technical verification** of the bypass's effect (fully playable,
   offline?) beyond secondary news/tracker assertions.

## 5. Conclusion (Onimusha-specific, explicit)

- **A day-one bypass of Onimusha's PC Denuvo is reported by multiple secondary
  sources** and attributed to the scene group **DENUVOWO** via the generic
  **hypervisor** method. Its existence as a *claim* is reasonably corroborated.
- **It is a partial, environment-level bypass, not a full crack, and not an
  Onimusha-specific vulnerability.** It is the generic 2026 hypervisor technique
  applied to this title, and it requires disabling Windows security.
- **No weakness unique to Onimusha's protection has been publicly demonstrated.**
  No primary technical analysis or reproducible PoC exists in the sources found;
  the game binary was not examined here.
- **Therefore: there is no demonstrated Onimusha-specific Denuvo vulnerability.**
  What exists is a reported instance of a known, game-agnostic environment-
  deception technique. Progressing to a game-specific conclusion is blocked by
  the missing items in §4 — primarily a primary technical artifact and the
  binary — which this environment does not provide and which this study will not
  fabricate.

---

## Sources (secondary; reported claims, not independently verified)
- [ixbt.games — "Denuvo bypassed in Onimusha on release day" (2026-09-04)](https://ixbt.games/en/news/2026/09/04/denuvo-obosli-v-onimusha-way-of-the-sword-v-den-reliza.html)
- [VGTimes — "Onimusha's Denuvo fell on launch day, bypassed by hypervisor"](https://vgtimes.com/gaming-news/166471-onimusha-way-of-the-swords-denuvo-fell-on-launch-day-bypassed-by-hypervisor.html)
- [isitcracked / CrackWatch — Onimusha crack status ("Hypervisor by DENUVOWO after 1 day")](https://isitcracked.com/game/onimusha-way-of-the-sword)
- [DSOGaming — Onimusha will have Denuvo, PC demo & requirements](https://www.dsogaming.com/news/onimusha-way-of-the-sword-will-have-denuvo-gets-pc-demo-pc-requirements/)
- [GamingOnLinux — Sep 4 release, first-run online setup](https://www.gamingonlinux.com/2026/07/onimusha-way-of-the-sword-releases-earlier-on-september-4-steam-deck-steamos-playable/)
- [ConsolePulse — PC requirements/benchmark, Denuvo 5-PC/day activation limit](https://consolepulse.com/pc/onimusha/guides/onimusha-way-of-the-sword-pc-requirements-benchmark)
- [allkeyshop — launches in September with Denuvo on PC](https://www.allkeyshop.com/blog/?p=3021036)
- [TechSpot — hypervisor-based cracks breaking Denuvo in hours (generic class context)](https://www.techspot.com/news/111897-hypervisor-based-cracks-breaking-denuvo-protections-hours.html)

*A how-to/tutorial video for the hypervisor bypass also appears in search results;
it is intentionally not linked or used here, as it is a procedure, not analysis.*
