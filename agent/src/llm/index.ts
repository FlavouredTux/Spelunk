import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import { assistantLLM } from "./assistant.js";
import { OpenAILLM } from "./openai.js";
import { OpenRouterLLM } from "./openrouter.js";
import type { LLM } from "./types.js";

export * from "./types.js";

// Provider selection: env vars first, then ~/.config/ember/agent.toml.
// Toml parsing is dumb-line-based — just enough for our two key forms:
//
//   key  = "sk-..."                          # one key
//   keys = ["sk-...", "sk-..."]              # multiple keys, round-robin
//
// Multiple keys are useful for free-tier providers (e.g. OpenRouter
// owl-alpha) where one account caps before a 200-worker cascade
// finishes round 0 — load can be split across accounts. The runtime
// rotates keys per makeLLM() call via a module-local counter, so
// concurrent workers get distributed across the available keys.

interface ProviderKeys {
    assistant: string[];
    openai: string[];
    openrouter: string[];
}

function loadKeys(): ProviderKeys {
    const out: ProviderKeys = {
        assistant: process.env.assistant_API_KEY ? [process.env.assistant_API_KEY] : [],
        openai:    process.env.OPENAI_API_KEY    ? [process.env.OPENAI_API_KEY]    : [],
        openrouter: process.env.OPENROUTER_API_KEY ? [process.env.OPENROUTER_API_KEY] : [],
    };
    const cfgPath = join(homedir(), ".config", "ember", "agent.toml");
    let raw: string;
    try { raw = readFileSync(cfgPath, "utf8"); } catch { return out; }

    const append = (sec: string, val: string) => {
        if (!val) return;
        if (sec === "assistant"  && !out.assistant.includes(val))  out.assistant.push(val);
        if (sec === "openai"     && !out.openai.includes(val))     out.openai.push(val);
        if (sec === "openrouter" && !out.openrouter.includes(val)) out.openrouter.push(val);
    };

    let section = "";
    for (const line of raw.split("\n")) {
        const t = line.trim();
        if (!t || t.startsWith("#")) continue;
        const m = /^\[(\w+)\]$/.exec(t);
        if (m) { section = m[1]; continue; }

        // keys = ["a", "b", ...]   array form (single-line)
        const arr = /^keys\s*=\s*\[(.+)\]\s*$/.exec(t);
        if (arr) {
            for (const m2 of arr[1].matchAll(/"([^"]*)"/g)) {
                append(section, m2[1]);
            }
            continue;
        }
        // key = "X"   single-key form (legacy / simple)
        const kv = /^(\w+)\s*=\s*"([^"]*)"$/.exec(t);
        if (kv && kv[1] === "key") append(section, kv[2]);
    }
    return out;
}

// Round-robin counter per provider. Survives the lifetime of the
// agent process — on a 200-worker cascade with 2 OpenRouter keys,
// workers 0/2/4/… get key A, 1/3/5/… get key B.
const _keyRotation: Record<string, number> = { assistant: 0, openai: 0, openrouter: 0 };

function pickKey(keys: string[], provider: string): string {
    if (keys.length === 0) throw new Error(`missing API key for ${provider}`);
    if (keys.length === 1) return keys[0];
    const i = _keyRotation[provider] % keys.length;
    _keyRotation[provider] = (_keyRotation[provider] + 1) | 0;
    return keys[i];
}

export function makeLLM(provider: "assistant" | "openai" | "openrouter"): LLM {
    const keys = loadKeys();
    switch (provider) {
        case "assistant":  return new assistantLLM(pickKey(keys.assistant, "assistant"));
        case "openai":     return new OpenAILLM(pickKey(keys.openai, "openai"));
        case "openrouter": return new OpenRouterLLM(pickKey(keys.openrouter, "openrouter"));
    }
}

// Diagnostic: how many keys are configured per provider. Surfaced via
// `ember-agent` status (used by the UI Settings drawer to show
// "OpenRouter: 2 keys").
export function keyCount(provider: "assistant" | "openai" | "openrouter"): number {
    return loadKeys()[provider].length;
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
