#!/usr/bin/env bash
# The project's CI, as a script so any host can run it.
#
#   scripts/ci.sh test      gcc build + full test suite (the reference job)
#   scripts/ci.sh clang     clang + libc++ build of the core and the
#                           toolchain-independent unit tests
#   scripts/ci.sh release   Release build of the CLI, stripped and packaged
#
# The reference job must run with the same gcc major the goldens were
# generated with (currently gcc 16): the golden files pin addresses and
# signature hashes that drift across compilers. Use a gcc:16 container
# if the host compiler differs. The dbg_* smoke tests need ptrace and
# perf, which containers rarely allow, so they are excluded here and run
# on a real Linux box.
set -euo pipefail
cd "$(dirname "$0")/.."

mode=${1:-test}
gen=()
command -v ninja >/dev/null 2>&1 && gen=(-G Ninja)

case "$mode" in
  test)
    cmake -S . -B build-ci "${gen[@]}" -DCMAKE_BUILD_TYPE=Release
    cmake --build build-ci
    ctest --test-dir build-ci --output-on-failure -E '^dbg_'
    ;;
  clang)
    CC=${CC:-clang} CXX=${CXX:-clang++} \
    CXXFLAGS="${CXXFLAGS:-} -stdlib=libc++" LDFLAGS="${LDFLAGS:-} -stdlib=libc++" \
      cmake -S . -B build-ci-clang "${gen[@]}" -DCMAKE_BUILD_TYPE=Release -DEMBER_BUILD_CLI=OFF
    cmake --build build-ci-clang --target ember_core ember_demangle_test \
                                          ember_annotations_resolver_test ember_sigs_test
    ctest --test-dir build-ci-clang --output-on-failure \
      -R '^(demangle_unit|annotations_resolver_unit|sigs_unit)$'
    ;;
  release)
    cmake -S . -B build-release "${gen[@]}" -DCMAKE_BUILD_TYPE=Release
    cmake --build build-release --target ember_cli
    strip build-release/cli/ember
    version=$(build-release/cli/ember --version | awk '{print $2}')
    tar czf "ember-${version}-linux-x86_64.tar.gz" -C build-release/cli ember
    echo "ember-${version}-linux-x86_64.tar.gz"
    ;;
  *)
    echo "usage: $0 [test|clang|release]" >&2
    exit 2
    ;;
esac
