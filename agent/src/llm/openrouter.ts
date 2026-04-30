import OpenAI from "openai";

import { OpenAILLM } from "./openai.js";

// OpenRouter speaks OpenAI Chat Completions on a different host. The only
// real difference is pricing: OpenRouter routes to many providers, each
// with their own per-token rate. The cost tally treats every model as
// "consult openrouter dashboard" and falls back to the conservative
// upstream-OpenAI numbers when the model isn't recognized.

type Price = { input: number; output: number; cache_read?: number; cache_write?: number };

const OPENROUTER_PRICING: Record<string, Price> = {
    // USD per 1M tokens. Cache_read is the discounted rate for tokens
    // matched against an upstream prefix cache. Best-effort floor for
    // budget guardrails, not invoicing.
    "assistant/assistant-opus-4.7":   { input: 15,   output: 75, cache_read: 1.5,  cache_write: 18.75 },
    "assistant/assistant-sonnet-4.6": { input: 3,    output: 15, cache_read: 0.3,  cache_write: 3.75 },
    "openai/gpt-5":                { input: 5,    output: 20 },
    "google/gemini-2.5-pro":       { input: 1.25, output: 5 },
    // DeepSeek auto-caches prompt prefixes; the cache rate is ~10% of
    // input. OpenRouter passes the cached_tokens counter through
    // unchanged, so the math holds regardless of which upstream host
    // serves the request.
    "deepseek/deepseek-v4-pro":    { input: 0.40, output: 1.20, cache_read: 0.04 },
    "deepseek/deepseek-v4-flash":  { input: 0.14, output: 0.28, cache_read: 0.0028 },
    "openrouter/owl-alpha":        { input: 0,    output: 0 },
    "deepseek/deepseek-v3.2":      { input: 0.27, output: 1.10, cache_read: 0.04 },
    "deepseek/deepseek-r1":        { input: 0.55, output: 2.19, cache_read: 0.14 },
};

export class OpenRouterLLM extends OpenAILLM {
    constructor(apiKey: string) {
        super(apiKey, "https://openrouter.ai/api/v1", "openrouter");
        // Re-construct the underlying OpenAI client with attribution headers.
        // OpenRouter reads HTTP-Referer + X-Title and surfaces them in the
        // dashboard's App column. Without these, every call shows as
        // "Unknown" — which makes per-app rate limits and free-tier quotas
        // hard to reason about.
        this.client = new OpenAI({
            apiKey,
            baseURL: "https://openrouter.ai/api/v1",
            defaultHeaders: {
                "HTTP-Referer": "https://github.com/FlavouredTux/Ember",
                "X-Title": "Ember Agent",
            },
        });
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
