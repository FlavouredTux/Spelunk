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
\`\`\`

The UI parses only this block; rename suggestions outside it are ignored. Use the literal identifiers visible in the snippet — never invent addresses (\`sub_140001000\` isn't valid if the snippet shows \`main\` or \`bb_1260\`).

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
      "Suggest a name for this function and for any unnamed args / locals whose role is evident from the APIs and strings in the body. Return ONLY the renames block — no prose. Omit suggestions you aren't confident in; an empty block is acceptable.",
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

// Parse the AI's renames block out of a response. The block is fenced
// as ```renames\n...\n``` per the system prompt. Tolerant of stray
// whitespace, missing fences (some models drop the language tag), and
// arrows in either direction (→ or ->).
export type RenameSuggestion = { from: string; to: string };
export function parseRenames(text: string): RenameSuggestion[] {
  const out: RenameSuggestion[] = [];
  // Try the labelled block first; fall back to any code fence whose
  // body is exclusively rename-shaped lines.
  const blocks: string[] = [];
  const labelled = text.matchAll(/```renames\s*\n([\s\S]*?)```/g);
  for (const m of labelled) blocks.push(m[1]);
  if (blocks.length === 0) {
    for (const m of text.matchAll(/```\s*\n([\s\S]*?)```/g)) {
      const body = m[1];
      // Heuristic: a fence that's all `X → Y` lines is a renames
      // block even without the label.
      const lines = body.split("\n").map((l) => l.trim()).filter(Boolean);
      if (lines.length > 0 && lines.every((l) => /(?:→|->)/.test(l))) {
        blocks.push(body);
      }
    }
  }
  for (const block of blocks) {
    for (const raw of block.split("\n")) {
      const m = raw.trim().match(/^([A-Za-z_][\w.:<>$]*)\s*(?:→|->)\s*([A-Za-z_][\w]*)\s*$/);
      if (m) out.push({ from: m[1], to: m[2] });
    }
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
