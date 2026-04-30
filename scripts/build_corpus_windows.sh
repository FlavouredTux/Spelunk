#!/bin/bash
# Build a Windows-targeted TEEF corpus.
#
# Output: $DEST/*.teef.tsv — one TSV per Windows DLL. Pass them all to
#   ember --recognize <bin> --corpus DIR/*.teef.tsv
# when analyzing a stripped Windows binary (PE32+, MSVC build, RAT
# samples, etc).
#
# Input: a directory containing **real Microsoft** Windows system
# DLLs (msvcrt.dll, ucrtbase.dll, vcruntime140.dll, msvcp140.dll,
# kernel32.dll, ntdll.dll, user32.dll, gdi32.dll, advapi32.dll,
# shell32.dll, ws2_32.dll, ole32.dll, …).
#
# IMPORTANT — DO NOT use Wine's DLLs.
#   Wine's system32 is a reimplementation. Its internal structure
#   differs from Microsoft's, so a Wine-built corpus would not match
#   the statically-linked CRT routines or inlined library code in
#   real Windows binaries. The TEEF fingerprints would point at the
#   wrong source. Use ACTUAL Microsoft DLLs from a real Windows
#   install (or a Windows VM, or a Microsoft Symbol Server pull).
#
# Two valid sources:
#   1. Copy from a real Windows install:
#        WIN_LIBS=/path/to/Windows/System32
#   2. Microsoft Symbol Server (use a downloader, point at output).
#
# Usage:
#   WIN_LIBS=/path/to/dlls bash scripts/build_corpus_windows.sh
#   DEST=/tmp/corpus_win bash scripts/build_corpus_windows.sh
#
# Each output TSV gets a leading `T<TAB>runtime<TAB><tag>` row so the
# recognizer's cross-language plausibility filter applies. Tags follow
# the same scheme as the Linux script: msvcrt / ucrt / vcruntime /
# cxxmsvc / winapi / c.

set -e

EMBER=${EMBER:-$(pwd)/build/cli/ember}
DEST=${DEST:-/tmp/corpus_windows_x86_64}
WIN_LIBS=${WIN_LIBS:-}

mkdir -p "$DEST"

if [ ! -x "$EMBER" ]; then
    echo "ERROR: $EMBER not found or not executable. Build ember first or set \$EMBER." >&2
    exit 1
fi

if [ -z "$WIN_LIBS" ] || [ ! -d "$WIN_LIBS" ]; then
    echo "ERROR: WIN_LIBS must point at a directory containing real Microsoft Windows DLLs." >&2
    echo "       Best path: copy from a real Windows install (Win10/11 System32)" >&2
    echo "       or use a Microsoft Symbol Server downloader." >&2
    echo "       Do NOT use Wine — its DLLs are reimplementations, not Microsoft binaries." >&2
    exit 1
fi

# Loud warning if Wine is the source.
case "$WIN_LIBS" in
    *.wine*|*wine/*)
        echo >&2
        echo "WARNING: WIN_LIBS looks like a Wine prefix." >&2
        echo "         Wine DLLs are reimplementations of the Win32 API — their" >&2
        echo "         internal structure differs from Microsoft's. A corpus built" >&2
        echo "         from them will NOT match real Windows binaries' inlined CRT" >&2
        echo "         routines or library code, leading to false negatives." >&2
        echo "         You probably want to grab real Microsoft DLLs from a" >&2
        echo "         Windows install instead. Override with FORCE_WINE=1 to" >&2
        echo "         continue anyway (e.g. for testing the script itself)." >&2
        if [ "${FORCE_WINE:-0}" != "1" ]; then exit 1; fi
        echo "         (FORCE_WINE=1 set, continuing)" >&2
        ;;
esac

# basename → runtime tag
runtime_tag_for() {
    local name=$(basename "$1" | tr 'A-Z' 'a-z')
    case "$name" in
        msvcrt.dll|msvcr*.dll)              echo msvcrt ;;
        ucrtbase*.dll|api-ms-win-crt-*.dll) echo ucrt ;;
        vcruntime*.dll)                      echo vcruntime ;;
        msvcp*.dll)                          echo cxxmsvc ;;
        kernel32.dll|kernelbase.dll|ntdll.dll|user32.dll|gdi32.dll|gdi32full.dll|advapi32.dll|shell32.dll|shlwapi.dll|ole32.dll|oleaut32.dll|ws2_32.dll|wininet.dll|winhttp.dll|crypt32.dll|bcrypt.dll|sechost.dll|combase.dll|rpcrt4.dll)
            echo winapi ;;
        *) echo c ;;
    esac
}

emit_runtime_header() {
    local tsv="$1"; local tag="$2"
    [ -z "$tag" ] && return 0
    [ ! -s "$tsv" ] && return 0
    if ! head -1 "$tsv" | grep -q "^T	runtime	"; then
        local tmp="$tsv.tmp.$$"
        printf "T\truntime\t%s\n" "$tag" > "$tmp"
        cat "$tsv" >> "$tmp"
        mv "$tmp" "$tsv"
    fi
}

# Walk the directory. Skip stub DLLs (api-ms-win-* are mostly forwarders;
# their TEEF would be tiny and add noise). Also skip non-DLL files.
echo "==> scanning $WIN_LIBS" >&2
shopt -s nullglob
for L in "$WIN_LIBS"/*.dll "$WIN_LIBS"/*.DLL; do
    [ -f "$L" ] || continue
    sz=$(stat -c%s "$L" 2>/dev/null || stat -f%z "$L" 2>/dev/null || echo 0)
    # Skip tiny forwarder stubs (<8 KB) — they're overwhelmingly api-ms-win-*
    # and don't contribute identifying fingerprints.
    [ "$sz" -lt 8192 ] && continue
    out="$DEST/$(basename "$L").teef.tsv"
    [ -s "$out" ] && continue
    echo "==> $(basename "$L") (${sz} bytes)" >&2
    if ! "$EMBER" --teef "$L" > "$out" 2>>"$DEST/build.log"; then
        echo "    FAILED — see $DEST/build.log" >&2
        rm -f "$out"
        continue
    fi
    tag=$(runtime_tag_for "$L")
    emit_runtime_header "$out" "$tag"
    f=$(grep -c '^F' "$out" 2>/dev/null || echo 0)
    c=$(grep -c '^C' "$out" 2>/dev/null || echo 0)
    s=$(grep -c '^S' "$out" 2>/dev/null || echo 0)
    echo "    F=$f C=$c S=$s runtime=$tag" >&2
done

echo >&2
echo "=== corpus summary ===" >&2
for L in "$DEST"/*.teef.tsv; do
    [ -e "$L" ] || continue
    f=$(grep -c '^F' "$L"); c=$(grep -c '^C' "$L")
    printf "  %-40s F=%-6d C=%-7d\n" "$(basename "$L")" "$f" "$c" >&2
done
total_f=$(grep -hc '^F' "$DEST"/*.teef.tsv 2>/dev/null | awk '{s+=$1} END{print s+0}')
total_c=$(grep -hc '^C' "$DEST"/*.teef.tsv 2>/dev/null | awk '{s+=$1} END{print s+0}')
echo "  TOTAL: F=$total_f C=$total_c across $(ls "$DEST"/*.teef.tsv 2>/dev/null | wc -l) TSVs" >&2
echo >&2
echo "Use with: $EMBER --recognize <binary> $(ls "$DEST"/*.teef.tsv 2>/dev/null | sed 's|^| --corpus |' | tr -d '\n') --recognize-threshold 0.85" >&2
