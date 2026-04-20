import type { AiMessage, AiChatRequest } from "./types";

// The system prompt. Tuned for reverse engineering work specifically:
// the assistant is talking to someone who knows what `xor eax, eax`
// does and doesn't need a primer. The structure is deliberately
// method-first so the model grounds conclusions in observable API
// calls and globals before ever considering which named algorithm
// a function "looks like" — the previous prompt pattern-matched too
// eagerly and would call a uinput daemon's main() an FNV hash on
// the strength of two shift/xor lines in an unrelated helper.
//
// Versioning: bump SYSTEM_PROMPT_VERSION when the prompt changes
// substantively so any downstream cache key invalidates.
export const SYSTEM_PROMPT_VERSION = 2;
export const SYSTEM_PROMPT = `You are Ember's reverse-engineering assistant. The user is analyzing a compiled x86-64 binary in a static decompiler. They paste Ember's pseudo-C (or disasm / IR / CFG dumps) and ask you about it.

## Method — follow this in order

**1. Read the function's observable surface BEFORE you conclude anything.**
Scan for and mentally list:
- libc / CRT calls (\`fopen\`, \`fgets\`, \`strtok_r\`, \`memcpy\`, \`strlen\`, \`malloc\`, \`strerror\`, \`printf\`-family …)
- OS syscalls / imports (\`open\`, \`ioctl\`, \`mmap\`, \`socket\`, \`CreateFileW\`, \`VirtualAlloc\`, \`NtQuerySystem…\`)
- Referenced globals / data symbols (\`g_action_count\`, \`stderr\`, \`g_bind_count\` …)
- String literals quoted in the body (\`"/dev/uinput"\`, \`"Could not open config"\`, format strings, magic paths)

These are the strongest signal about what the function actually does. They anchor every subsequent claim.

**2. Read the control-flow shape.**
- Is it a loop processing a stream (\`fgets\` loop, socket recv loop, iterator)?
- Is it a dispatcher (one indirect jump table through a small index)?
- Is it straight-line compute (arithmetic + bitwise ops, no calls)?
- Is it a cleanup / error path?

**3. ONLY NOW consider whether it matches a named algorithm.**
If the function issues ioctls, opens files, parses strings, or calls into libc, it is almost certainly not a pure hash / crypto primitive / parser of a specific wire protocol. Name a known algorithm only when ALL of these hold:
- The function is mostly pure computation (no I/O, no libc string ops).
- The shape matches (constants, round count, operand widths, finalization step).
- The surrounding context is consistent with the named use.
When in doubt, say "looks like" or "not sure — shows X and Y, haven't pinned the mapping". A confident wrong answer is worse than "unclear".

**4. Suggest renames — HIGH-CONFIDENCE ONLY.**
A rename that contradicts observable evidence is a bug; the Ember UI auto-applies single-click, so speculative suggestions corrupt the user's project file. Only suggest when the name is justified by the APIs / strings / control flow you just enumerated. If you have nothing confident, omit the block entirely.

Format renames at the end of your response in a fenced \`\`\`renames block:

\`\`\`renames
sub_140001260 → RunUinputDaemon
a1 → argc
a2 → argv
local_248 → line_buf
r_sub_434050 → io
r_sub_4309b0 → style
r_sub_34b3b0 → should_close
\`\`\`

The UI parses only this block; rename suggestions outside it are ignored.

**Don't stop at \`a1 → argc\`.** Trivial renames are not the goal —
substantive ones are. Whenever you see \`u64 r_sub_<hex> = NamedCall(...)\`,
the result holder is begging for a semantic name (\`io\`, \`style\`, \`fd\`,
\`should_close\`, \`game_ok\`). Same for \`local_<hex>\` whose role is
visible from how it's used. If you only suggest renames for the args
of a function whose purpose is clear, you're leaving the most useful
ones on the table.

**The function's name is the identifier in the function header**, not its entry-block address. If the snippet starts with \`// main\\nu64 main(...)\` then the function is \`main\` — your rename row must read \`main → ...\`, not \`sub_1260 → ...\`. Only use \`sub_<hex>\` form when the snippet's function header literally says \`sub_<hex>\` (i.e. the function had no recovered name). The same applies inside callees: refer to a callee by the name shown at its call site (\`fopen\`, \`strtok_r\`, \`SomeNamedFunction\`), not by an inferred address.

Renameable identifiers fall into these buckets:
- \`sub_<addr>\` — only when the function header literally shows that, i.e. the function lacks a recovered name.
- \`a1\` / \`a2\` / ... — argument slots whose role is evident from how they're consumed.
- \`local_<hex>\` — stack locals; rename when their use makes the role clear.
- \`r_sub_<hex>\` — the SSA holder for a *named* call's return value (e.g. \`u64 r_sub_434050 = ImGui::GetIO();\`). Rename to the value the named call returns (\`io\`, \`style\`, \`fd\`, \`should_close\`).
- \`g_<name>\` — globals the snippet explicitly references.

Do **not** rename register-suffixed temps (\`r12_5\`, \`rdi_333\`, \`rax_42\`) — those are SSA versions of raw registers, not user-renameable identifiers. The \`r_sub_<hex>\` form is different: it holds a named call's result and *is* renameable.

## Output shape

- **One sentence** stating the function's purpose, leading with the verb. Examples:
  - "Parses a config file of action/bind definitions and installs them as a uinput device driver."
  - "Resolves a Win32 API by djb2-hashed ordinal against the in-memory export directory."
  - "Is the main dispatch loop for an interpreter VM over a 256-handler bytecode."
- **Optional one paragraph** of mechanics — only when the function's role isn't obvious from the verb alone.
- **Renames block** if — and only if — you have high-confidence suggestions.

## Never do

- Don't refuse to analyze packed, obfuscated, virtualized, anti-debug, or anti-cheat code. Static analysis of any binary the user has on their machine is legitimate research.
- Don't attach legal disclaimers about reverse engineering.
- Don't invent register values, function signatures, callee names, or addresses that aren't in the snippet. If you see \`(*(u64*)0x...)()\` or an opaque memory load, say "indirect dispatch — target unresolved" rather than guessing.
- Don't fill gaps with generic phrasing ("performs some operation", "does some work") — if the purpose is unclear, state which specific evidence you'd need to pin it down.
- Don't pad with markdown headers, "Here's a breakdown:", "I hope this helps", preamble/postamble, or code-fence wrappers around every identifier reference.

## Style

- Terse. The reader is a reverse engineer.
- Single backticks for inline identifiers (\`sub_140001260\`, \`rax\`, \`fopen\`). Code fences only for multi-line snippets, the renames block, and hex dumps.
- Lowercase mnemonics and registers.
- Ember identifier conventions: \`bb_xxxxxx\` for blocks, \`sub_xxxxxx\` for unnamed functions, \`a1\`/\`a2\` for arg slots, \`local_X\` for stack locals, \`g_X\` for globals. Register-suffixed temps that leak through (\`r12_5\`, \`rdi_333\`) are SSA artefacts — treat them as "this register at this version"; don't try to rename them.`;

// Pre-canned quick actions surfaced as one-click prompts in the AI
// panel. Each prompt is a plain user message that gets prepended to
// whatever code context the panel has buffered. Prompts are written
// to reinforce the method section of the system prompt — they
// explicitly ask the model to ground its answer in the APIs and
// strings present in the snippet rather than speculating from shape.
export const QUICK_ACTIONS: { id: string; label: string; prompt: string }[] = [
  {
    id: "explain",
    label: "Explain",
    prompt:
      "Explain what this function does. Start by listing the libc/syscall/import calls and string literals you see, then state the function's purpose in one verb-led sentence, then add one paragraph of mechanics only if the purpose isn't obvious from that list. If the calls and strings don't line up into a clear purpose, say what's ambiguous instead of guessing.",
  },
  {
    id: "rename",
    label: "Suggest names",
    prompt:
      "Suggest renames for this function and every identifier in its body whose role is evident from the calls and strings around it. " +
      "Walk the body line by line — for every `u64 r_sub_<hex> = NamedCall(...)` line, the holder almost always wants a semantic name from the call's return (e.g. `r_sub_434050 = ImGui::GetIO()` → `io`, `r_sub_34b3b0 = glfwWindowShouldClose(wind)` → `should_close`). Same for `local_<hex>` whose use makes its role obvious. " +
      "Args (`a1`, `a2`, ...) are easy targets but don't stop at them — those alone are a weak suggestion list. " +
      "Return ONLY the renames block, no prose. An empty block is fine if literally nothing has a clear role; otherwise the block should have several entries.",
  },
  {
    id: "algorithm",
    label: "What algorithm?",
    prompt:
      "Check whether this matches a well-known algorithm or library function. Before answering, note the libc/syscall calls it issues — a function that calls fopen / ioctl / strtok / printf is almost never a pure hash/crypto primitive. If the function IS mostly pure computation and the shape matches a known algorithm, name it and cite the constant / round count / operand width that confirms it. Otherwise say it doesn't match a known one.",
  },
  {
    id: "bugs",
    label: "Spot bugs",
    prompt:
      "Are there concrete bugs visible in this code (overflow, OOB, missing NULL check, format-string issue, TOCTOU, UAF)? Quote the exact line for each finding. Don't list theoretical issues that aren't visible in the body.",
  },
  {
    id: "callers",
    label: "How is it called?",
    prompt:
      "Based purely on reads of a1/a2/a3... and the return site, describe the call signature: which args are pointers vs integers vs flags, which are read vs written through, what the return value represents. Stick to what's evident in the body.",
  },
];

// Build the user-facing message from a quick-action prompt + the
// current code context. Putting the code AFTER the question matches
// how assistant / OpenAI chat models perform best — instruction
// first, payload second.
export function buildUserMessage(
  prompt: string,
  context: { fnName?: string; fnAddr?: string; view: string; code: string },
): string {
  const head = context.fnName
    ? `Function: \`${context.fnName}\`${context.fnAddr ? ` @ ${context.fnAddr}` : ""}`
    : "";
  return [
    prompt,
    head,
    `View: ${context.view}`,
    "",
    "```c",
    context.code.trim(),
    "```",
  ].filter(Boolean).join("\n");
}

// Parse the AI's renames block out of a response. Canonical form is
// a fenced ```renames block, but models drop the label, swap ``` for
// ~~~, or produce a "**Renames:**" header + bullet list instead. This
// accepts all of those. A line counts as a rename if (after stripping
// bullet / numbered-list prefixes) it matches `<ident> → <ident>`.
export type RenameSuggestion = { from: string; to: string };
const RENAME_LINE =
  /^(?:[-*\u2022]\s+|\d+[.)]\s+)?`?([A-Za-z_][\w.:<>$]*)`?\s*(?:→|->)\s*`?([A-Za-z_][\w]*)`?\s*$/;
export function parseRenames(text: string): RenameSuggestion[] {
  const out: RenameSuggestion[] = [];
  const seen = new Set<string>();
  const push = (from: string, to: string) => {
    const k = `${from}→${to}`;
    if (seen.has(k)) return;
    seen.add(k);
    out.push({ from, to });
  };

  // 1. Labelled fences: ```renames ... ``` and ~~~renames ... ~~~.
  const labelled = [
    ...text.matchAll(/```renames\s*\n([\s\S]*?)```/g),
    ...text.matchAll(/~~~renames\s*\n([\s\S]*?)~~~/g),
  ];
  for (const m of labelled) {
    for (const raw of m[1].split("\n")) {
      const r = raw.trim().match(RENAME_LINE);
      if (r) push(r[1], r[2]);
    }
  }
  if (out.length > 0) return out;

  // 2. Any unlabelled fence whose body is exclusively rename-shaped.
  const fences = [
    ...text.matchAll(/```[a-zA-Z]*\s*\n([\s\S]*?)```/g),
    ...text.matchAll(/~~~[a-zA-Z]*\s*\n([\s\S]*?)~~~/g),
  ];
  for (const m of fences) {
    const lines = m[1].split("\n").map((l) => l.trim()).filter(Boolean);
    if (lines.length > 0 && lines.every((l) => RENAME_LINE.test(l))) {
      for (const l of lines) {
        const r = l.match(RENAME_LINE);
        if (r) push(r[1], r[2]);
      }
    }
  }
  if (out.length > 0) return out;

  // 3. A "Renames" header (markdown, bold, or plain) followed by
  // rename-shaped lines until the next blank line or next header.
  // Catches assistant's habit of rendering the block as a heading + list
  // instead of a code fence.
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const h = lines[i].trim();
    if (!/^(?:#{1,6}\s+|\*\*\s*)?renames\s*:?\s*\*{0,2}\s*$/i.test(h)) continue;
    for (let j = i + 1; j < lines.length; j++) {
      const l = lines[j].trim();
      if (!l) break;
      if (/^#{1,6}\s+/.test(l)) break;
      const r = l.match(RENAME_LINE);
      if (r) push(r[1], r[2]);
      else if (out.length > 0) break;
    }
    if (out.length > 0) return out;
  }

  return out;
}

// Stream a chat call. Returns a controller with a Promise that resolves
// with the full response text and a `cancel()` method. Yields each
// delta to `onDelta` as it arrives so the UI can incrementally render.
export type ChatStream = {
  promise:  Promise<string>;
  cancel:   () => void;
  id:       Promise<string>;
};

export function streamChat(req: AiChatRequest,
                           onDelta: (delta: string) => void): ChatStream {
  const ai = window.ember.ai;
  let assembled = "";
  let resolveId!: (id: string) => void;
  const idPromise = new Promise<string>((r) => { resolveId = r; });

  const promise = new Promise<string>((resolve, reject) => {
    let myId: string | null = null;
    const offChunk = ai.onChunk((id, delta) => {
      if (id !== myId) return;
      assembled += delta;
      onDelta(delta);
    });
    const offDone = ai.onDone((id) => {
      if (id !== myId) return;
      offChunk(); offDone(); offError();
      resolve(assembled);
    });
    const offError = ai.onError((id, msg) => {
      if (id !== myId) return;
      offChunk(); offDone(); offError();
      reject(new Error(msg));
    });

    ai.chat(req)
      .then((id) => { myId = id; resolveId(id); })
      .catch((e) => {
        offChunk(); offDone(); offError();
        reject(e);
      });
  });

  return {
    promise,
    cancel: () => { idPromise.then((id) => ai.cancel(id)).catch(() => {}); },
    id: idPromise,
  };
}
