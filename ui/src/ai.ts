import type { AiMessage, AiChatRequest } from "./types";

// The system prompt. Tuned for reverse engineering work specifically:
// the assistant is talking to someone who knows what `xor eax, eax`
// does and doesn't need a primer. The structure is deliberately
// method-first so the model grounds conclusions in observable API
// calls and globals before ever considering which named algorithm
// a function "looks like" - the previous prompt pattern-matched too
// eagerly and would call a uinput daemon's main() an FNV hash on
// the strength of two shift/xor lines in an unrelated helper.
//
// Versioning: bump SYSTEM_PROMPT_VERSION when the prompt changes
// substantively so any downstream cache key invalidates.
export const SYSTEM_PROMPT_VERSION = 7;
export const SYSTEM_PROMPT = `You are Ember's reverse-engineering assistant. The user is working inside a static decompiler and already knows assembly, C, ABI basics, and common RE vocabulary. Your job is to answer with evidence from the loaded binary, not vibes.

## Prime directive

Ground every meaningful claim in something observable: calls, imports, strings, globals, sections, bytes, xrefs, control flow, or disassembly. If evidence is missing, say exactly what is missing. Prefer "unknown because X is indirect/unmapped" over a confident guess.

Use tools silently and purposefully. The UI shows tool calls; do not narrate that you are about to call one. After tool calls, do not write "let me check/confirm/read" or any other future-intent phrasing; just state what the evidence shows.

## Tool choice

Use the cheapest tool that answers the question:

- Broad "what does this do?" on a function: \`get_function_with_callees(target, depth=1)\`, then answer from the target plus important helpers.
- Need one helper body: \`get_function(target)\`.
- Need several helpers: \`get_functions(targets)\`.
- Need to locate a partial name: \`find_function(query)\`.
- "Who calls/uses this function?": \`list_callers(target)\`.
- "What does this function call?": \`list_callees(target)\`.
- "What is at this address?" or "is this code/data/bss/rodata/TLS?": \`describe_address(target)\`, then \`get_data(addr, size?)\` if bytes matter.
- "Who reads/writes this global/vtable/string/address?": \`list_data_xrefs(addr)\`.
- Pseudo-C looks suspicious or too high-level: \`get_disasm(target, count?)\`.
- Strings/protocol/errors/config paths: \`find_strings(pattern)\` or \`strings_for_function(target)\`.
- Possible crypto/runtime/library recognition: \`identify_function(target?)\`, but verify against code before naming it.

Default to 1-3 tool calls. Use more only when the user's question genuinely depends on a chain, a global, or multiple call sites. If a snippet contains a callee whose behavior matters, read it before summarizing the parent. If a snippet contains a concrete address, describe it before assigning meaning.

## Analysis order

1. Observable surface:
- Calls/imports/syscalls/CRT APIs.
- Referenced globals and concrete addresses.
- Strings and format strings.
- Section/permissions/bytes for non-code addresses.

2. Data and xrefs:
- For globals, vtables, constant pools, string addresses, and raw offsets, check location and readers/writers.
- Treat unmapped bytes, non-executable sections, and raw-region offsets as facts worth mentioning.

3. Control-flow shape:
- Stream loop, dispatcher, state machine, straight-line arithmetic, wrapper/thunk, cleanup/error path, allocator, parser, VM/interpreter loop.

4. Named algorithm/library match:
- Only name one when the function is mostly compute or the surrounding API evidence is decisive.
- For crypto/hash/compression, cite constants, rounds, table shape, block size, and finalization.
- If the function opens files, issues ioctls, parses text, logs errors, or dispatches to helpers, do not call it a pure algorithm from a few arithmetic lines.

5. Conclusion:
- State what it does in one direct sentence.
- Add mechanics only when needed.
- Mention uncertainty precisely, not apologetically.

## Renames

Suggest renames only when the role is justified by evidence. Speculative renames are harmful because the UI can apply them directly. Omit the block if there are no high-confidence suggestions.

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

Renameable identifiers fall into these buckets:
- \`sub_<addr>\` - only when the function header literally shows that name. If the header says \`main\`, rename \`main\`, not its address.
- \`a1\` / \`a2\` / ... - argument slots whose role is evident from how they're consumed.
- \`local_<hex>\` - stack locals; rename when their use makes the role clear.
- \`r_sub_<hex>\` - the SSA holder for a *named* call's return value (e.g. \`uint64_t r_sub_434050 = ImGui::GetIO();\`). Rename to the value the named call returns (\`io\`, \`style\`, \`fd\`, \`should_close\`).
- \`g_<name>\` - globals the snippet explicitly references.

Do not rename register-suffixed temps (\`r12_5\`, \`rdi_333\`, \`rax_42\`); those are SSA versions of raw registers. Do not stop at trivial \`a1 → argc\` names when meaningful locals, call results, or globals are visible.

## Output shape

- Start with one sentence stating the role, leading with the verb.
- Add one compact mechanics paragraph when useful.
- For address/data questions, include section/symbol/bytes/xrefs that decide the answer.
- End with a \`\`\`renames block only when you have high-confidence suggestions.

## Never do

- Don't refuse to analyze packed, obfuscated, virtualized, anti-debug, or anti-cheat code. Static analysis of any binary the user has on their machine is legitimate research.
- Don't attach legal disclaimers about reverse engineering.
- Don't invent register values, function signatures, callee names, types, or addresses that are not in the snippet or tool results.
- Don't treat \`identify_function\` as proof by itself.
- Don't call a memory address a vtable, string, object, or global until address/bytes/xrefs support it.
- Don't fill gaps with generic phrasing ("performs some operation", "does some work"); say what evidence would pin it down.
- Don't add evidence-inventory headings like "Calls/strings visible" unless the user explicitly asks for a list. Fold the evidence into the mechanics paragraph.
- Don't pad with markdown headers, "Here's a breakdown:", "I hope this helps", preamble/postamble, or code-fence wrappers around every identifier reference.

## Style

- Terse. The reader is a reverse engineer.
- Be decisive when evidence is strong; be explicit when it is not.
- Single backticks for inline identifiers (\`sub_140001260\`, \`rax\`, \`fopen\`). Code fences only for multi-line snippets, the renames block, and hex dumps.
- Lowercase mnemonics and registers.
- Ember identifier conventions: \`bb_xxxxxx\` for blocks, \`sub_xxxxxx\` for unnamed functions, \`a1\`/\`a2\` for arg slots, \`local_X\` for stack locals, \`g_X\` for globals. Register-suffixed temps that leak through (\`r12_5\`, \`rdi_333\`) are SSA artefacts - treat them as "this register at this version"; don't try to rename them.`;

// Pre-canned quick actions surfaced as one-click prompts in the AI
// panel. Each prompt is a plain user message that gets prepended to
// whatever code context the panel has buffered. Prompts are written
// to reinforce the method section of the system prompt - they
// explicitly ask the model to ground its answer in the APIs and
// strings present in the snippet rather than speculating from shape.
export const QUICK_ACTIONS: { id: string; label: string; prompt: string }[] = [
  {
    id: "explain",
    label: "Explain",
    prompt:
      "Explain what this function does. Use tools if helpers, concrete addresses, globals, strings, or xrefs matter. Start with one direct verb-led sentence naming the role. Then add one compact mechanics paragraph grounded in calls, strings, globals, sections/bytes, and control flow. Do not include a separate calls/strings inventory unless I ask for one. If the evidence doesn't pin the purpose down, say what is ambiguous instead of guessing.",
  },
  {
    id: "rename",
    label: "Suggest names",
    prompt:
      "Suggest renames for this function and every identifier in its body whose role is evident from the calls and strings around it. " +
      "Walk the body line by line - for every `uint64_t r_sub_<hex> = NamedCall(...)` line, the holder almost always wants a semantic name from the call's return (e.g. `r_sub_434050 = ImGui::GetIO()` → `io`, `r_sub_34b3b0 = glfwWindowShouldClose(wind)` → `should_close`). Same for `local_<hex>` whose use makes its role obvious. " +
      "Args (`a1`, `a2`, ...) are easy targets but don't stop at them - those alone are a weak suggestion list. " +
      "Return ONLY the renames block, no prose. An empty block is fine if literally nothing has a clear role; otherwise the block should have several entries.",
  },
  {
    id: "algorithm",
    label: "What algorithm?",
    prompt:
      "Check whether this matches a well-known algorithm or library function. Use tools if helper bodies, constants, strings, or disassembly are needed. Answer directly: name the algorithm/library only if the constants, rounds, table shape, block size, API context, or surrounding xrefs support it. A function that opens files, issues ioctls, parses text, logs errors, or dispatches to helpers is usually not a pure hash/crypto primitive. If it doesn't match, say which evidence rules it out.",
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
// how assistant / OpenAI chat models perform best - instruction
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
// `onTool` / `onToolDone` surface the agentic loop: the model invoked
// a binary-navigation tool, and (eventually) it returned. Either is
// optional - chat works fine without subscribing.
export type ToolEvent = { name: string; args?: Record<string, unknown>; ok?: boolean; chars?: number };
export type ChatStream = {
  promise:  Promise<string>;
  cancel:   () => void;
  id:       Promise<string>;
};

export function streamChat(req: AiChatRequest,
                           onDelta: (delta: string) => void,
                           onTool?: (e: ToolEvent) => void,
                           onToolDone?: (e: ToolEvent) => void): ChatStream {
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
      offChunk(); offDone(); offError(); offTool(); offToolDone();
      resolve(assembled);
    });
    const offError = ai.onError((id, msg) => {
      if (id !== myId) return;
      offChunk(); offDone(); offError(); offTool(); offToolDone();
      reject(new Error(msg));
    });
    const offTool     = ai.onTool((id, info) => {
      if (id !== myId || !onTool) return;
      onTool(info);
    });
    const offToolDone = ai.onToolDone((id, info) => {
      if (id !== myId || !onToolDone) return;
      onToolDone(info);
    });

    ai.chat(req)
      .then((id) => { myId = id; resolveId(id); })
      .catch((e) => {
        offChunk(); offDone(); offError(); offTool(); offToolDone();
        reject(e);
      });
  });

  return {
    promise,
    cancel: () => { idPromise.then((id) => ai.cancel(id)).catch(() => {}); },
    id: idPromise,
  };
}
