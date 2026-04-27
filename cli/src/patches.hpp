#pragma once

namespace ember::cli {

struct Args;

// --apply-patches FILE -o OUT: load FILE (one `vaddr_hex bytes_hex` per
// line, comments + blanks tolerated), translate each VA to a file
// offset via the binary's section table, splice the bytes into a copy
// of the original file, write to args.output_path. One-shot, no
// analysis runs.
int run_apply_patches(const Args& args);

}  // namespace ember::cli
