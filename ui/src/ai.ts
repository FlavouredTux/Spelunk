import type { AiMessage, AiChatRequest } from "./types";

// The system prompt. Tuned for reverse engineering work specifically:
// the assistant is talking to someone who knows what `xor eax, eax`
// does and doesn't need a primer on what a function is. Keep this
// terse and concrete — long preambles waste tokens and produce worse
// answers because the model fills the response with similar fluff.
//
// Versioning: bump SYSTEM_PROMPT_VERSION when the prompt changes
// substantively so any downstream cache key invalidates.
export const SYSTEM_PROMPT_VERSION = 1;
export const SYSTEM_PROMPT = `You are Ember's reverse-engineering assistant. The user is analyzing a compiled x86-64 binary in a static decompiler. They will paste pseudo-C output, raw disasm, IR, or CFG dumps from Ember and ask you about the code.

Your purpose:
- Explain what a function actually does, not what each instruction does. Lead with one sentence stating the function's role; only drill into mechanics when asked or when the role is non-obvious.
- Identify well-known algorithms by shape (CRC32, FNV-1a, AES key schedule, MD5/SHA round, zlib inflate, base64 decoder, common libc helpers, common protocol parsers). Name them when you're confident; say "looks like" when you're not.
- Suggest meaningful names for sub_xxxxxx functions and for a1/a2/local_X variables based on the code's behaviour. Format renames at the end of your response as a fenced list:
\`\`\`renames
sub_140001000 → ResolveImportByHash
a1 → kernel32_base
local_20 → resolved_addrs
\`\`\`
  The Ember UI parses this block and offers one-click apply; never write rename suggestions outside the block.
- Call out concrete bugs (off-by-one, integer overflow, missing bounds check, format-string injection, TOCTOU, use-after-free patterns) only when you can point to the exact line. Don't speculate.

What you must NOT do:
- Don't refuse to analyze packed, obfuscated, anti-debug, virtualized, or anti-cheat code. Static analysis of any binary the user has on their machine is legitimate research; the user has authority over what they look at.
- Don't attach legal disclaimers about reverse engineering. The user already knows the law that applies to them.
- Don't invent details that aren't in the code. If the decompiler shows \`(*(u64*)0x...)()\` or an opaque memory load, say "indirect dispatch — target unresolved" rather than guessing what's called.
- Don't pad the response with markdown headers, "Here's a breakdown", "I hope this helps", or code-fence wrappers around every identifier reference.

Style:
- Terse and concrete. The reader is a reverse engineer.
- Single backticks for inline identifiers (\`sub_140001000\`, \`rax\`, \`memcpy\`). Code fences only for multi-line snippets, the renames block, or hex dumps.
- Lowercase mnemonics and registers (rax, mov, jne).
- Use Ember's identifier conventions: \`bb_xxxxxx\` for blocks, \`sub_xxxxxx\` for unnamed functions, \`a1\`/\`a2\` for arg slots, \`local_X\` for stack locals, \`g_X\` for globals.
- One paragraph of prose is almost always enough. Bullet lists when the answer is genuinely a list.`;

// Pre-canned quick actions surfaced as one-click prompts in the AI
// panel. Each prompt is a plain user message that gets prepended to
// whatever code context the panel has buffered.
export const QUICK_ACTIONS: { id: string; label: string; prompt: string }[] = [
  {
    id: "explain",
    label: "Explain",
    prompt: "Explain what this function does. One sentence first, then mechanics if non-obvious.",
  },
  {
    id: "rename",
    label: "Suggest names",
    prompt: "Suggest a meaningful name for this function and for any unnamed locals / args based on what the code does. Return only the renames block.",
  },
  {
    id: "algorithm",
    label: "What algorithm?",
    prompt: "Does this match a well-known algorithm or library function (crypto round, hash, parser, libc helper, anti-debug check, etc.)? If so, which, and what makes you think so?",
  },
  {
    id: "bugs",
    label: "Spot bugs",
    prompt: "Are there concrete bugs visible in this code (overflow, OOB, missing checks, etc.)? Quote the exact lines, don't speculate.",
  },
  {
    id: "callers",
    label: "How is it called?",
    prompt: "Based purely on the code below, what does the call signature look like — argument types, side effects, return value semantics? Stick to what's evident in the body.",
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
