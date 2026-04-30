import OpenAI from "openai";

import type {
    ChatRequest,
    ChatResponse,
    ContentBlock,
    LLM,
    Message,
    StopReason,
    ToolDef,
} from "./types.js";

// OpenAI Chat Completions adapter. Also serves as the base for OpenRouter,
// which speaks the same wire format with a different baseURL.
//
// No prompt caching is exposed in the response (OpenAI auto-caches >1024
// tokens but doesn't bill differently in a way our cost tally tracks
// turn-by-turn). pricing() returns input/output only.

export class OpenAILLM implements LLM {
    protected client: OpenAI;
    protected providerName: string;

    constructor(apiKey: string, baseURL?: string, providerName = "openai") {
        this.client = new OpenAI({ apiKey, baseURL });
        this.providerName = providerName;
    }

    name() { return this.providerName; }

    // Hook for subclasses (e.g. OpenRouter) to inject provider-specific
    // request fields like `provider: { order: [...] }`. Default is none.
    protected extraBody(_model: string): Record<string, unknown> { return {}; }

    pricing(model: string) {
        // USD per 1M tokens. Best-effort defaults for OpenAI-direct models.
        // OpenRouter prices are per-model and would override; for now we
        // accept the conservative-ish OpenAI numbers as a tally floor.
        if (model.startsWith("gpt-5")) return { input: 5, output: 20 };
        if (model.startsWith("gpt-4o")) return { input: 2.5, output: 10 };
        if (model.includes("o1")) return { input: 15, output: 60 };
        return { input: 3, output: 12 };
    }

    async chat(req: ChatRequest): Promise<ChatResponse> {
        const messages: OpenAI.Chat.ChatCompletionMessageParam[] = [
            { role: "system", content: req.system },
            ...req.messages.flatMap(toOpenAIMessages),
        ];

        const tools: OpenAI.Chat.ChatCompletionTool[] = req.tools.map((t) => ({
            type: "function",
            function: {
                name: t.name,
                description: t.description,
                parameters: t.input_schema as unknown as Record<string, unknown>,
            },
        }));

        const resp = await this.client.chat.completions.create({
            model: req.model,
            messages,
            tools: tools.length ? tools : undefined,
            max_tokens: req.max_tokens,
            temperature: req.temperature,
            ...this.extraBody(req.model),
        } as OpenAI.Chat.ChatCompletionCreateParamsNonStreaming);

        const choice = resp.choices[0];
        const content: ContentBlock[] = [];
        if (choice.message.content) {
            content.push({ type: "text", text: choice.message.content });
        }
        for (const tc of choice.message.tool_calls ?? []) {
            if (tc.type !== "function") continue;
            content.push({
                type: "tool_use",
                id: tc.id,
                name: tc.function.name,
                input: safeParseJson(tc.function.arguments),
            });
        }

        // OpenAI-compatible providers surface cached prefix tokens in
        // usage.prompt_tokens_details.cached_tokens. DeepSeek auto-caches
        // any prefix that re-appears within ~24h; OpenRouter passes the
        // counter through. We split the reported prompt_tokens into
        // (cached, fresh) for accurate cost tallying.
        const promptDetails = (resp.usage as { prompt_tokens_details?: { cached_tokens?: number } } | undefined)
            ?.prompt_tokens_details;
        const cached = promptDetails?.cached_tokens ?? 0;
        const totalPrompt = resp.usage?.prompt_tokens ?? 0;

        return {
            content,
            stop_reason: mapStopReason(choice.finish_reason),
            usage: {
                input_tokens: Math.max(0, totalPrompt - cached),
                output_tokens: resp.usage?.completion_tokens ?? 0,
                cache_read_input_tokens: cached,
            },
            model: resp.model,
        };
    }
}

// OpenAI requires assistant tool_use and the matching tool_result to be
// split across separate messages with specific roles. One of our internal
// messages may expand into multiple wire-level messages.
function toOpenAIMessages(m: Message): OpenAI.Chat.ChatCompletionMessageParam[] {
    if (m.role === "user") {
        const toolResults = m.content.filter(
            (b): b is Extract<ContentBlock, { type: "tool_result" }> =>
                b.type === "tool_result");
        const texts = m.content.filter(
            (b): b is Extract<ContentBlock, { type: "text" }> =>
                b.type === "text");

        const out: OpenAI.Chat.ChatCompletionMessageParam[] = [];
        for (const tr of toolResults) {
            out.push({
                role: "tool",
                tool_call_id: tr.tool_use_id,
                content: tr.content,
            });
        }
        if (texts.length) {
            out.push({ role: "user", content: texts.map((t) => t.text).join("\n") });
        }
        return out.length ? out : [{ role: "user", content: "" }];
    }
    // assistant
    const text = m.content
        .filter((b) => b.type === "text")
        .map((b) => (b as { text: string }).text)
        .join("\n");
    const tool_calls = m.content
        .filter((b) => b.type === "tool_use")
        .map((b) => {
            const tu = b as Extract<ContentBlock, { type: "tool_use" }>;
            return {
                id: tu.id,
                type: "function" as const,
                function: { name: tu.name, arguments: JSON.stringify(tu.input) },
            };
        });
    return [{
        role: "assistant",
        content: text || null,
        tool_calls: tool_calls.length ? tool_calls : undefined,
    }];
}

function mapStopReason(r: string | null | undefined): StopReason {
    switch (r) {
        case "stop": return "end_turn";
        case "tool_calls": return "tool_use";
        case "length": return "max_tokens";
        default: return "other";
    }
}

function safeParseJson(s: string): Record<string, unknown> {
    try { return JSON.parse(s); } catch { return {}; }
}
