# Security policy

ember parses untrusted binaries — ELF, Mach-O, PE, minidumps, raw
memory regions, PDB sidecars. Bugs in the parsers, the disassembler,
the lifter, or the debugger backends are a real attack surface for
anyone using ember on hostile inputs (malware samples, CTF
challenges, captured payloads).

If you find a memory-safety issue, parser crash on a crafted input,
or any vulnerability that could be triggered by a malicious binary,
please **do not file a public issue**. Use GitHub's private
vulnerability reporting on this repository:

> **Security tab → Report a vulnerability**

(direct link: https://github.com/FlavouredTux/Ember/security/advisories/new)

This routes the report straight to the maintainer without exposing it
publicly.

## What counts as a vulnerability

- Heap / stack corruption from a crafted binary, sidecar, or trace.
- Out-of-bounds reads in any parser or decoder.
- Path traversal or arbitrary-write through annotation files,
  declarative scripts, or cache paths.
- Anything in the debugger backends that lets a tracee escape its
  intended sandbox.

## What doesn't

- Crashes from intentionally-malformed inputs that the tool already
  flags as invalid (open an issue if it's user-hostile, not a sec
  report).
- Performance bugs (file an issue).
- Output quality complaints (file an issue).

## Response

I'm a solo maintainer. Expect a first reply within a few days.
Coordinated disclosure is welcome — propose a timeline that works for
you.
