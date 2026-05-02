# Contributing to ember

ember is MIT-licensed and welcomes contributions to the core tool. This
document covers what we accept, what we don't, and why.

## What we accept

- **Bug fixes and algorithm improvements** anywhere in `core/`, `cli/`,
  or `ui/`. Open a PR; include a test if you're fixing user-visible
  behavior.
- **New analyses, decoders, lifters, structurer passes.** Same flow.
  See the style notes at the bottom of this file.
- **Documentation.** Fixes to `docs/`, the README, this file, code
  comments. Typos through reorganization, all welcome.
- **Test fixtures you built yourself.** A small C/Rust/asm source plus
  a build script that produces a tiny binary — fair game, since
  you produced the binary from scratch.
- **Issue reports.** Bug reports with reproducible inputs are valuable
  even without a fix attached.

By submitting a PR you agree your contribution is licensed under the
project's MIT license.

## What we don't accept

### Corpus recipes, prebuilt corpora, or annotations for third-party binaries

ember Pro ships curated TEEF corpora as a paid product. The build
recipes for those corpora are open, but **we don't accept community
contributions to them.**

Reasons:

- Building a recipe requires verifying we have the right to process and
  redistribute hashes derived from third-party binaries. That's
  license-clearance work we can't outsource without a contributor
  license agreement we don't want to maintain.
- Annotations layered on top of reverse-engineered runtimes are
  themselves potentially copyrightable. Accepting them from contributors
  without a CLA muddies the licensing of the resulting corpus product.
- Recipes that point at proprietary or grey-area binary sources are a
  reputational liability we'd rather control directly.

If you want a runtime supported, **open an issue** describing it. If we
agree it's useful and we can clear the licensing, we'll build it
ourselves.

### Reverse-engineered work product on closed-source software

PRs that include disassembly, decompilation output, or annotations
derived from closed-source binaries we don't have a license to
redistribute will be closed without merge. This includes anti-cheat
internals, DRM internals, game runtime internals, and anything covered
by a license that prohibits RE.

The tool is designed for that work. The repository is not the place to
publish the output of it.

## Reporting security issues

For vulnerabilities in ember itself (parser bugs, debugger memory
safety, etc.), see `SECURITY.md` for private disclosure via GitHub's
security advisories.

## Code style

- C++23, CMake, warnings-as-errors on.
- stdlib only — no Capstone, Zydis, Ghidra, LLVM, or vendored deps.
  Don't propose adding libraries.
- Terse and decisive. No speculative error handling, no fallbacks for
  cases that can't happen, no validation outside system boundaries.
- Don't add comments that narrate the obvious. Only note non-obvious
  invariants, workarounds, or surprises.
- Goldens live in `tests/golden/`. When you intentionally change
  behaviour that shifts output, update goldens in the same commit and
  narrate what changed in the commit message.
- Build + run tests before pushing:
  ```sh
  cmake --build build
  ctest --test-dir build
  ```
