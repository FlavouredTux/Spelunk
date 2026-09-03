# Contributing to ember

ember is MIT-licensed and welcomes contributions to the core tool. This
document covers what we accept, what we don't, and why.

## What we accept

- **Bug fixes and algorithm improvements** anywhere in `core/` or `cli/`.
  Send a merge request or a patch; include a test if you're fixing
  user-visible behavior.
- **New analyses, decoders, lifters, structurer passes.** Same flow.
  See the style notes at the bottom of this file.
- **Documentation.** Fixes to `docs/`, the README, this file, code
  comments. Typos through reorganization, all welcome.
- **Test fixtures you built yourself.** A small C/Rust/asm source plus
  a build script that produces a tiny binary - fair game, since
  you produced the binary from scratch.
- **Issue reports.** Bug reports with reproducible inputs are valuable
  even without a fix attached.

By submitting a change you agree it is licensed under the project's
MIT license.

## What we don't accept

### Corpus recipes, prebuilt corpora, or annotations for third-party binaries

The corpus build recipes under `scripts/` are open, but **we don't
accept community contributions to them**, nor prebuilt corpora or
annotations derived from third-party binaries.

Reasons:

- A recipe has to be checked for the right to process and redistribute
  hashes derived from third-party binaries. That's license-clearance
  work we can't outsource without a contributor license agreement we
  don't want to maintain.
- Annotations layered on top of reverse-engineered runtimes are
  themselves potentially copyrightable. Accepting them without a CLA
  muddies the licensing of the result.
- Recipes that point at proprietary or grey-area binary sources are a
  liability we'd rather control directly.

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

## Reporting bugs

A useful report has the exact command line, what happened (output,
error, or the wrong pseudo-C), what you expected, and the ember version
or commit, OS and build type. A reproducer helps most: a small binary
or the build script that produces one. Public binaries (distro
packages, open-source builds) are the easiest to chase.

Runtime and library recognition requests: name the runtime, where its
binaries come from and under what license, and what recognizing it
would unlock. Public references are welcome; binary samples and
annotations from reverse-engineered builds are not (see above).

## Reporting security issues

For vulnerabilities in ember itself (parser bugs, debugger memory
safety, etc.), see `SECURITY.md`; report them privately, not in the
tracker.

## Continuous integration

`scripts/ci.sh test` is the reference job: a gcc build and the full
suite minus the `dbg_*` smoke tests, which need ptrace. Run it with the
gcc major the goldens were generated with (gcc 16 today; a `gcc:16`
container works). `scripts/ci.sh clang` builds the core with clang and
libc++ and runs the toolchain-independent unit tests; `scripts/ci.sh
release` builds, strips and packages the CLI. Wire those three into
whatever the host offers.

## Code style

- C++23, CMake, warnings-as-errors on.
- stdlib only - no Capstone, Zydis, Ghidra, LLVM, or vendored deps.
  Don't propose adding libraries.
- Terse and decisive. No speculative error handling, no fallbacks for
  cases that can't happen, no validation outside system boundaries.
- Don't add comments that narrate the obvious. Only note non-obvious
  invariants, workarounds, or surprises.
- One topic per translation unit. When a file outgrows ~1,500 lines,
  split it by concern and put what the pieces share in a sibling
  `<name>_internal.hpp` under a named namespace (`ember::x64_lift`,
  `ember::cli::dbg`, ...). Helpers used by a single unit stay in that
  unit's anonymous namespace. Public headers under `core/include` never
  include internal ones.
- Goldens live in `tests/golden/`. When you intentionally change
  behaviour that shifts output, update goldens in the same commit and
  narrate what changed in the commit message.
- Build + run tests before pushing:
  ```sh
  cmake --build build
  ctest --test-dir build
  ```
