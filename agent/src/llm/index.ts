import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import { assistantLLM } from "./assistant.js";
import { OpenAILLM } from "./openai.js";
import { OpenRouterLLM } from "./openrouter.js";
import type { LLM } from "./types.js";

export * from "./types.js";

// Provider selection: env vars first, then ~/.config/ember/agent.toml.
// Toml parsing is dumb-line-based — just enough for `key = "value"` under
// `[provider]` sections. Real grammar would be over-engineered for this.

interface ProviderKeys {
    assistant?: string;
    openai?: string;
    openrouter?: string;
}

function loadKeys(): ProviderKeys {
    const out: ProviderKeys = {
        assistant: process.env.assistant_API_KEY,
        openai: process.env.OPENAI_API_KEY,
        openrouter: process.env.OPENROUTER_API_KEY,
    };
    const cfgPath = join(homedir(), ".config", "ember", "agent.toml");
    let raw: string;
    try { raw = readFileSync(cfgPath, "utf8"); } catch { return out; }

    let section = "";
    for (const line of raw.split("\n")) {
        const t = line.trim();
        if (!t || t.startsWith("#")) continue;
        const m = /^\[(\w+)\]$/.exec(t);
        if (m) { section = m[1]; continue; }
        const kv = /^(\w+)\s*=\s*"([^"]*)"$/.exec(t);
        if (!kv) continue;
        if (kv[1] !== "key") continue;
        // env vars win over toml.
        if (section === "assistant" && !out.assistant)  out.assistant  = kv[2];
        if (section === "openai" && !out.openai)        out.openai     = kv[2];
        if (section === "openrouter" && !out.openrouter) out.openrouter = kv[2];
    }
    return out;
}

export function makeLLM(provider: "assistant" | "openai" | "openrouter"): LLM {
    const keys = loadKeys();
    switch (provider) {
        case "assistant":
            if (!keys.assistant) throw new Error("missing assistant_API_KEY");
            return new assistantLLM(keys.assistant);
        case "openai":
            if (!keys.openai) throw new Error("missing OPENAI_API_KEY");
            return new OpenAILLM(keys.openai);
        case "openrouter":
            if (!keys.openrouter) throw new Error("missing OPENROUTER_API_KEY");
            return new OpenRouterLLM(keys.openrouter);
    }
}

// Pick the right provider for a given model id. assistant models go
// direct to assistant for first-class caching. Everything else through
// OpenRouter unless the user has OPENAI_API_KEY set and asked for it.
export function providerForModel(model: string):
    "assistant" | "openai" | "openrouter"
{
    if (model.startsWith("assistant-")) return "assistant";
    if (model.includes("/")) return "openrouter";   // openrouter style: vendor/model
    return "openai";
}
