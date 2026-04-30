import { OpenAILLM } from "./openai.js";

// OpenRouter speaks OpenAI Chat Completions on a different host. The only
// real difference is pricing: OpenRouter routes to many providers, each
// with their own per-token rate. The cost tally treats every model as
// "consult openrouter dashboard" and falls back to the conservative
// upstream-OpenAI numbers when the model isn't recognized.

const OPENROUTER_PRICING: Record<string, { input: number; output: number }> = {
    // USD per 1M tokens. Update as needed; this is best-effort floor for
    // budget guardrails, not invoicing.
    "assistant/assistant-opus-4.7":   { input: 15,  output: 75 },
    "assistant/assistant-sonnet-4.6": { input: 3,   output: 15 },
    "openai/gpt-5":                { input: 5,   output: 20 },
    "google/gemini-2.5-pro":       { input: 1.25, output: 5 },
    "deepseek/deepseek-r1":        { input: 0.55, output: 2.19 },
};

export class OpenRouterLLM extends OpenAILLM {
    constructor(apiKey: string) {
        super(apiKey, "https://openrouter.ai/api/v1", "openrouter");
    }

    pricing(model: string) {
        return OPENROUTER_PRICING[model] ?? super.pricing(model);
    }

    // OpenRouter routes a single model across many provider hosts. Some hosts
    // are flaky (silent context truncation, sluggish first-token, occasional
    // schema-noncompliant tool calls). Pinning the official provider for a
    // family avoids that — we forfeit a fraction of cost savings for
    // determinism, which agents need more than humans do.
    protected extraBody(model: string): Record<string, unknown> {
        if (model.startsWith("deepseek/")) {
            return { provider: { order: ["DeepSeek"], allow_fallbacks: false } };
        }
        if (model.startsWith("assistant/")) {
            return { provider: { order: ["assistant"], allow_fallbacks: false } };
        }
        if (model.startsWith("openai/")) {
            return { provider: { order: ["OpenAI"], allow_fallbacks: false } };
        }
        if (model.startsWith("google/")) {
            return { provider: { order: ["Google"], allow_fallbacks: false } };
        }
        return {};
    }
}
