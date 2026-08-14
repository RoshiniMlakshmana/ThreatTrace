# Licensing Notes

**Status: no `LICENSE` file exists at the repository root.** This is a packaging decision that requires the repository owner's explicit choice — it is deliberately **not** made by this checkpoint. Per this block's own instructions: "DO NOT choose one silently unless prior project context explicitly selected one." No prior project context selected one, so none was added.

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
