# Licensing Notes

**Status: `LICENSE` (Apache License, Version 2.0, unmodified official text) is present at the repository root as of v0.1.0.** The repository owner explicitly chose Apache-2.0; this was not inferred, defaulted, or chosen automatically by any earlier checkpoint (see the superseded note preserved below for that history).

## NOTICE file: not added, and not currently required

Apache-2.0's NOTICE-propagation obligation (License Section 4(d)) is triggered only when *redistributing* a Work that itself shipped with a NOTICE file — i.e. when this repository vendors/ships someone else's Apache-licensed source as part of its own distribution. That does not happen here:

- `references/atomic-red-team/` and `references/hayabusa-sample-evtx/` are **not tracked by git** (`.gitignore` excludes both under "Third-party repositories") — nothing from either is actually distributed as part of this repository's own history or releases.
- Nmap, Nuclei, ZAP, httpx, Katana, and OWASP Juice Shop are never vendored as source/binaries inside this git repository. Nuclei/httpx/Katana binaries are downloaded from their own official GitHub releases *during the Docker image build* (see `Dockerfile`); Nmap is installed from the Debian package repository at build time; ZAP and Juice Shop run as their own official, separately-pulled Docker images (`zaproxy/zap-stable`, `bkimminich/juice-shop`) via `docker-compose.yml`. None of their source or binary content is committed to, or distributed from, this repository.

Since no tracked, distributed content in this repository carries an inbound NOTICE obligation, adding a NOTICE file would only manufacture attribution claims this repository has no actual basis for. None was added. If that changes in the future (e.g. vendoring real third-party source directly into the tree), this decision should be revisited.

## Third-party tool licensing stays separate from ThreatTrace's own license

ThreatTrace's Apache-2.0 license covers ThreatTrace's own source code in this repository only. It does not relicense, and must never be read as relicensing, Nmap, Nuclei, ZAP, httpx, Katana, or OWASP Juice Shop — each remains under its own upstream project's own license, unaffected by anything in this repository. See each project's own repository for its actual license terms.

---

*The section below is preserved as historical record of the pre-v0.1.0 checkpoint's own reasoning, before the owner made the Apache-2.0 decision above.*

**Status (superseded): no `LICENSE` file exists at the repository root.** This is a packaging decision that requires the repository owner's explicit choice — it is deliberately **not** made by this checkpoint. Per this block's own instructions: "DO NOT choose one silently unless prior project context explicitly selected one." No prior project context selected one, so none was added.

## Why this matters before any public/open-source step

Without a `LICENSE` file, default copyright law applies: nobody outside the copyright holder has any license to use, modify, or redistribute this code, regardless of the repository's public/private visibility on any hosting platform. If ThreatTrace is intended to be shared, published, or used as open-source software (per this project's own "16 — GitHub / reproducible/open-source packaging" framing), a `LICENSE` file is a prerequisite the owner needs to add deliberately, not a formality.

## Things the owner should decide before choosing a license

- Whether any third-party code embedded or vendored in this repository (see `references/atomic-red-team/` and `references/hayabusa-sample-evtx/`, each already carrying its own license) imposes any constraint on how ThreatTrace's own code can be licensed.
- Whether the intended audience is purely research/educational (a license like MIT/Apache-2.0/BSD is common for that) or something with different terms (e.g. a source-available or non-commercial license, given the project touches offensive-security tooling).
- Whether contributions from others are expected, which affects whether a `CONTRIBUTING.md` and a contributor license agreement (CLA) question should be resolved at the same time as the license itself.

## What this checkpoint did NOT do

- Did not add an MIT, Apache-2.0, BSD, GPL, or any other license file.
- Did not add SPDX license headers to any source file.
- Did not modify `package.json`/`pyproject.toml`-style `license` metadata fields (none currently exist in this repository).

## Recommended next step

The repository owner should explicitly choose a license (or explicitly choose to keep the repository proprietary/all-rights-reserved) and either add the corresponding `LICENSE` file directly, or ask a future session to add a specific, named license.
