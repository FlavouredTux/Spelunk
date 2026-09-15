#!/usr/bin/env bash
# The project's CI, as a script so any host can run it.
#
#   scripts/ci.sh test      gcc build + full test suite (the reference job)
#   scripts/ci.sh clang     clang + libc++ build of the core and the
#                           toolchain-independent unit tests
#   scripts/ci.sh release   Release build of the CLI, stripped and packaged
#   scripts/ci.sh asan      gcc build with AddressSanitizer + UBSan, full suite
#   scripts/ci.sh fuzz      clang libFuzzer targets for the loaders and
#                           decoders, each run for FUZZ_SECONDS (default 30)
#                           against a corpus seeded from the test fixtures
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
      cmake -S . -B build-ci-clang "${gen[@]}" -DCMAKE_BUILD_TYPE=Release -DSPELUNK_BUILD_CLI=OFF
    cmake --build build-ci-clang --target spelunk_core spelunk_demangle_test \
                                          spelunk_annotations_resolver_test spelunk_sigs_test \
                                          spelunk_import_sigs_test
    ctest --test-dir build-ci-clang --output-on-failure \
      -R '^(demangle_unit|annotations_resolver_unit|sigs_unit|import_sigs_unit)$'
    ;;
  release)
    cmake -S . -B build-release "${gen[@]}" -DCMAKE_BUILD_TYPE=Release
    cmake --build build-release --target spelunk_cli
    strip build-release/cli/spelunk
    version=$(build-release/cli/spelunk --version | awk '{print $2}')
    tar czf "spelunk-${version}-linux-x86_64.tar.gz" -C build-release/cli spelunk
    echo "spelunk-${version}-linux-x86_64.tar.gz"
    ;;
  asan)
    cmake -S . -B build-ci-asan "${gen[@]}" -DCMAKE_BUILD_TYPE=RelWithDebInfo -DSPELUNK_SANITIZE=ON
    cmake --build build-ci-asan
    ctest --test-dir build-ci-asan --output-on-failure -E '^dbg_'
    ;;
  fuzz)
    CC=${CC:-clang} CXX=${CXX:-clang++} \
      cmake -S . -B build-fuzz "${gen[@]}" -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DSPELUNK_SANITIZE=ON -DSPELUNK_BUILD_FUZZERS=ON -DSPELUNK_BUILD_CLI=OFF \
        -DBUILD_TESTING=OFF
    cmake --build build-fuzz
    # Seed each loader corpus with the fixtures of its format; the
    # decoders get every fixture, headers and all, as raw bytes. The
    # generated (Mach-O, PE, minidump, REL) fixtures only exist in a build
    # directory that staged them, so look in the usual ones too.
    fixture_dirs=(tests/fixtures)
    for d in build/tests/fixtures build-ci/tests/fixtures; do
      [ -d "$d" ] && fixture_dirs+=("$d")
    done

    fixture_manifest=build-fuzz/fuzz-fixtures.list
    find "${fixture_dirs[@]}" -type f \
      \( -name '*.prebuilt' -o -name '*.rel' -o ! -name '*.*' \) \
      -print0 > "$fixture_manifest"
    while IFS= read -r -d '' f; do
      for t in fuzz_x64 fuzz_arm64 fuzz_arm32 fuzz_ppc fuzz_ppc_le; do mkdir -p "build-fuzz/corpus/$t"; cp -f "$f" "build-fuzz/corpus/$t/"; done
      if [[ "$f" == *.rel ]]; then
        mkdir -p build-fuzz/corpus/fuzz_rel
        cp -f "$f" build-fuzz/corpus/fuzz_rel/
      fi
      case "$(file -b "$f" 2>/dev/null)" in
        ELF*)      mkdir -p build-fuzz/corpus/fuzz_elf;      cp -f "$f" build-fuzz/corpus/fuzz_elf/ ;;
        PE32*)     mkdir -p build-fuzz/corpus/fuzz_pe;       cp -f "$f" build-fuzz/corpus/fuzz_pe/ ;;
        Mach-O*)   mkdir -p build-fuzz/corpus/fuzz_macho;    cp -f "$f" build-fuzz/corpus/fuzz_macho/ ;;
        Mini\ DuMP*) mkdir -p build-fuzz/corpus/fuzz_minidump; cp -f "$f" build-fuzz/corpus/fuzz_minidump/ ;;
        *MSF*|*PDB*) mkdir -p build-fuzz/corpus/fuzz_pdb;    cp -f "$f" build-fuzz/corpus/fuzz_pdb/ ;;
      esac
    done < "$fixture_manifest"
    # Inputs that found bugs before are committed under tests/fuzz/corpus
    # and replayed first on every run.
    [ -d tests/fuzz/corpus ] && cp -r tests/fuzz/corpus/. build-fuzz/corpus/
    # Golden-test fixture generation is disabled in this lean fuzz build.
    # Generate one valid input per loader after every corpus copy so a clean
    # checkout has useful seeds and stale cached inputs cannot replace them.
    mkdir -p build-fuzz/corpus/{fuzz_macho,fuzz_pe,fuzz_minidump,fuzz_dol,fuzz_rel,fuzz_pdb}
    "${PYTHON:-python3}" tests/fixtures/make_macho_tiny.py \
      build-fuzz/corpus/fuzz_macho/valid-macho
    "${PYTHON:-python3}" tests/fixtures/make_pe_tiny.py \
      build-fuzz/corpus/fuzz_pe/valid-pe
    "${PYTHON:-python3}" tests/fixtures/make_minidump_tiny.py \
      build-fuzz/corpus/fuzz_minidump/valid-minidump.dmp
    "${PYTHON:-python3}" tests/fixtures/make_ppc64_tiny.py dol-scalar \
      build-fuzz/corpus/fuzz_dol/valid.dol
    "${PYTHON:-python3}" -B tests/fixtures/make_wii_rel.py \
      build-fuzz/corpus/fuzz_rel/valid.rel
    "${PYTHON:-python3}" tests/fixtures/make_pe_pdb.py \
      build-fuzz/corpus/fuzz_pe/valid-pdb-pe \
      build-fuzz/corpus/fuzz_pdb/valid.pdb
    rc=0
    for t in fuzz_elf fuzz_pe fuzz_macho fuzz_minidump fuzz_dol fuzz_rel fuzz_pdb fuzz_x64 fuzz_arm64 fuzz_arm32 fuzz_ppc fuzz_ppc_le; do
      mkdir -p "build-fuzz/corpus/$t"
      echo "== $t"
      "build-fuzz/tests/fuzz/$t" -max_total_time="${FUZZ_SECONDS:-30}" -max_len=65536 \
        -artifact_prefix="build-fuzz/crash-$t-" "build-fuzz/corpus/$t" 2>&1 | tail -3 || rc=1
    done
    exit $rc
    ;;
  *)
    echo "usage: $0 [test|clang|release|asan|fuzz]" >&2
    exit 2
    ;;
esac
