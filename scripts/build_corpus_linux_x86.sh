#!/usr/bin/env bash
# Build a TEEF library-recognition corpus for Linux x86-64.
#
# Output: $DEST/*.teef.tsv — one TSV per library. Pass them to
#   ember --recognize <bin> --corpus DIR/*.teef.tsv
# to auto-rename functions in stripped Linux binaries that statically
# link any of these runtimes.
#
# Coverage in this script:
#   - glibc, libstdc++, libgcc_s, libm, libpthread (system runtime)
#   - libssl, libcrypto, libz, libzstd, libbz2 (common compression / crypto)
#   - libxxhash (just to demo small-lib coverage)
#   - Rust std (via the toolchain's libstd-*.so plus a built-in
#     "extractor" Rust binary that exercises a wide std API surface
#     so the resulting concrete std-fn instantiations are in the corpus)
#
# Run from repo root or anywhere; expects ember to be at build/cli/ember
# unless you override $EMBER.

set -euo pipefail

EMBER=${EMBER:-build/cli/ember}
DEST=${DEST:-/tmp/corpus_linux_x86}
mkdir -p "$DEST"

if [ ! -x "$EMBER" ]; then
    echo "ERROR: $EMBER not found or not executable. Build ember first or set \$EMBER." >&2
    exit 1
fi

# ---- Stock Linux libraries ----
SYSTEM_LIBS=(
    /usr/lib/libc.so.6
    /usr/lib/libstdc++.so.6
    /usr/lib/libgcc_s.so.1
    /usr/lib/libm.so.6
    /usr/lib/libpthread.so.0
    /usr/lib/libssl.so.3
    /usr/lib/libcrypto.so.3
    /usr/lib/libz.so.1
    /usr/lib/libzstd.so.1
    /usr/lib/libbz2.so.1.0
    /usr/lib/libxxhash.so.0
    # Distro-specific paths (Debian/Ubuntu): try the multiarch dirs too
    /usr/lib/x86_64-linux-gnu/libc.so.6
    /usr/lib/x86_64-linux-gnu/libstdc++.so.6
    /usr/lib/x86_64-linux-gnu/libssl.so.3
)
# Map basename → runtime tag for the cross-language plausibility filter.
# Tag goes in a leading `T<TAB>runtime<TAB><tag>` row that the recognizer
# applies to every F/C row in the file. Empty tag → no row, behaves as
# "match any runtime" (back-compat).
runtime_tag_for() {
    case "$(basename "$1")" in
        libstdc++.so*)               echo libstdcxx ;;
        libssl.so*|libcrypto.so*)    echo openssl ;;
        libc.so*|libpthread.so*|ld-linux*) echo libc ;;
        libstd-*.so)                 echo rust ;;
        *.so*|*.elf|*) echo c ;;
    esac
}

emit_runtime_header() {
    local tsv="$1"; local tag="$2"
    [ -z "$tag" ] && return 0
    [ ! -s "$tsv" ] && return 0
    # Prepend `T<TAB>runtime<TAB><tag>\n` once. Skip if already present.
    if ! head -1 "$tsv" | grep -q "^T	runtime	"; then
        local tmp="$tsv.tmp.$$"
        printf "T\truntime\t%s\n" "$tag" > "$tmp"
        cat "$tsv" >> "$tmp"
        mv "$tmp" "$tsv"
    fi
}

for L in "${SYSTEM_LIBS[@]}"; do
    [ -e "$L" ] || continue
    REAL=$(readlink -f "$L")
    out="$DEST/$(basename "$L").teef.tsv"
    [ -s "$out" ] && continue
    echo "==> $L (real: $REAL)" >&2
    "$EMBER" --teef "$REAL" > "$out" 2>>"$DEST/build.log"
    emit_runtime_header "$out" "$(runtime_tag_for "$L")"
    echo "    F=$(grep -c '^F' "$out") C=$(grep -c '^C' "$out") runtime=$(runtime_tag_for "$L")" >&2
done

# ---- Rust std + ecosystem ----
# The toolchain ships libstd as a .so; fingerprint it directly. Then
# build a small Rust extractor binary that exercises common std APIs
# so concrete monomorphisations of generic functions land in the
# corpus too (those don't exist in the rlibs as ELF code; they're
# instantiated at link time per consuming binary).
if command -v rustc >/dev/null 2>&1; then
    SYSROOT=$(rustc --print sysroot)
    RUST_STD_SO=$(find "$SYSROOT" -name 'libstd-*.so' 2>/dev/null | head -1)
    if [ -n "$RUST_STD_SO" ] && [ ! -s "$DEST/rust_std.teef.tsv" ]; then
        echo "==> rust std .so: $RUST_STD_SO" >&2
        "$EMBER" --teef "$RUST_STD_SO" > "$DEST/rust_std.teef.tsv" 2>>"$DEST/build.log"
        emit_runtime_header "$DEST/rust_std.teef.tsv" rust
        echo "    F=$(grep -c '^F' "$DEST/rust_std.teef.tsv") C=$(grep -c '^C' "$DEST/rust_std.teef.tsv") runtime=rust" >&2
    fi

    if command -v cargo >/dev/null 2>&1 && [ ! -s "$DEST/rust_extractor.teef.tsv" ]; then
        echo "==> building Rust corpus extractor..." >&2
        WORK=$(mktemp -d)
        cp scripts/rust_corpus_extractor/main.rs scripts/rust_corpus_extractor/Cargo.toml "$WORK/" 2>/dev/null || {
            echo "    (extractor source not found at scripts/rust_corpus_extractor/, skipping)" >&2
            rm -rf "$WORK"
        }
        if [ -d "$WORK" ] && [ -f "$WORK/Cargo.toml" ]; then
            (cd "$WORK" && cargo build --release 2>>"$DEST/build.log")
            EXTRACTOR=$(find "$WORK/target/release" -maxdepth 1 -type f -executable | head -1)
            if [ -n "$EXTRACTOR" ]; then
                "$EMBER" --teef "$EXTRACTOR" > "$DEST/rust_extractor.teef.tsv" 2>>"$DEST/build.log"
                emit_runtime_header "$DEST/rust_extractor.teef.tsv" rust
                echo "    F=$(grep -c '^F' "$DEST/rust_extractor.teef.tsv") C=$(grep -c '^C' "$DEST/rust_extractor.teef.tsv") runtime=rust" >&2
            fi
            rm -rf "$WORK"
        fi
    fi
fi

echo >&2
echo "=== corpus summary ===" >&2
for L in "$DEST"/*.teef.tsv; do
    [ -e "$L" ] || continue
    f=$(grep -c '^F' "$L"); c=$(grep -c '^C' "$L")
    printf "  %-40s F=%-6d C=%-7d\n" "$(basename "$L")" "$f" "$c" >&2
done
total_f=$(grep -c '^F' "$DEST"/*.teef.tsv | awk -F: '{s+=$2} END{print s}')
total_c=$(grep -c '^C' "$DEST"/*.teef.tsv | awk -F: '{s+=$2} END{print s}')
echo "  TOTAL: F=$total_f C=$total_c across $(ls "$DEST"/*.teef.tsv 2>/dev/null | wc -l) TSVs" >&2
echo >&2
echo "Use with: $EMBER --recognize <binary> $(ls "$DEST"/*.teef.tsv 2>/dev/null | sed 's|^| --corpus |' | tr -d '\n') --recognize-threshold 0.85" >&2
