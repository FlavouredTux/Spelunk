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
}
