# Contributing to Spelunk

Bug fixes, improvements to the CLI or Qt GUI, and documentation changes are
welcome. For larger changes, open an issue first to discuss the approach.

## Reporting bugs

Include the Spelunk version or commit, your OS and compiler, the command you
ran, and what happened compared to what you expected. A small source file and
the command used to compile it make a useful reproducer.

Report security vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## Pull requests

Keep each pull request focused on one change. Explain what it fixes and how
you tested it. Add a regression test for bug fixes where practical.

Use small, self-contained test fixtures with source and build instructions.
Only include files you have permission to redistribute.

## Building and testing

See the [README](README.md#build) for CLI and Qt build instructions.

```sh
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Golden output files live in `tests/golden/`. If a change intentionally alters
the output, update the affected files and explain why in the pull request.
Committed `.prebuilt` fixtures keep addresses stable across compiler versions;
use `scripts/refresh_fixtures.sh` when changing their source.

Additional checks are available through `scripts/ci.sh`: `test`, `clang`,
`asan`, and `fuzz`.

## Code style

- Use C++23 and follow the surrounding code.
- Keep the core analysis independent of external disassembly libraries.
- Keep files focused. Split large implementations by concern.
- Keep internal headers out of the public API under `core/include/`.
- Explain non-obvious behavior in comments.

Contributions are licensed under the project's [MIT license](LICENSE).
