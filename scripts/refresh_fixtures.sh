#!/usr/bin/env bash
# Rebuild the compiled test fixtures from their sources, replace the
# committed tests/fixtures/<name>.prebuilt binaries with the result, and
# regenerate the goldens against them.
#
# The goldens record addresses and function sizes, so they are tied to
# the exact bytes of the fixture binaries. Those binaries are committed so
# the suite does not depend on whichever gcc happens to be installed; run
# this only when a fixture source changes or when deliberately moving the
# suite to a new toolchain, and commit the .prebuilt files and the golden
# changes together.
set -euo pipefail
cd "$(dirname "$0")/.."

gen=()
command -v ninja >/dev/null 2>&1 && gen=(-G Ninja)
cmake -S . -B build-fixtures "${gen[@]}" -DCMAKE_BUILD_TYPE=Release -DSPELUNK_COMPILE_FIXTURES=ON
cmake --build build-fixtures

names=$(grep -oE '^\s*spelunk_build_fixture\([A-Za-z0-9_]+' tests/CMakeLists.txt | sed -E 's/.*\(//')
for name in $names; do
    cp "build-fixtures/tests/fixtures/$name" "tests/fixtures/$name.prebuilt"
done
echo "refreshed $(echo "$names" | wc -w) fixture binaries with $(cc --version | head -1)"

UPDATE_GOLDEN=1 ctest --test-dir build-fixtures --output-on-failure -E '^dbg_' || true
ctest --test-dir build-fixtures --output-on-failure -E '^dbg_'
git status --short tests/fixtures tests/golden
