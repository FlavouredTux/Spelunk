// Provider-neutral message + tool-use shapes.
//
// The provider adapters (assistant.ts, openai.ts, openrouter.ts) translate
// between this and the vendor-native shape. The agent loop in worker.ts
// only ever touches these types, so swapping providers is a one-line config
// change.

export type Role = "user" | "assistant";

export interface TextBlock {
    type: "text";
    text: string;
}

export interface ToolUseBlock {
    type: "tool_use";
    id: string;
    name: string;
    input: Record<string, unknown>;
}

export interface ToolResultBlock {
    type: "tool_result";
    tool_use_id: string;
    content: string;
    is_error?: boolean;
}

export type ContentBlock = TextBlock | ToolUseBlock | ToolResultBlock;

export interface Message {
    role: Role;
    content: ContentBlock[];
}

// JSON-Schema subset accepted by all three providers. No oneOf/$ref/allOf.
export interface ToolSchema {
    type: "object";
    properties: Record<string, unknown>;
    required?: string[];
}

export interface ToolDef {
    name: string;
    description: string;
    input_schema: ToolSchema;
}

export interface Usage {
    input_tokens: number;
    output_tokens: number;
    cache_creation_input_tokens?: number;
    cache_read_input_tokens?: number;
}

export type StopReason =
    | "end_turn"
    | "tool_use"
    | "max_tokens"
    | "stop_sequence"
    | "other";

export interface ChatResponse {
    content: ContentBlock[];      // text + tool_use blocks (no tool_result on assistant side)
    stop_reason: StopReason;
    usage: Usage;
    model: string;
}

export interface ChatRequest {
    model: string;
    system: string;               // cached prefix
    tools: ToolDef[];             // also cached
    messages: Message[];          // dynamic suffix
    max_tokens: number;
    temperature?: number;
}

export interface LLM {
    name(): string;
    chat(req: ChatRequest): Promise<ChatResponse>;
    // Per-1M-token prices for cost tallying. cache_read/creation may be
    // absent on providers that don't expose explicit caching.
    pricing(model: string): {
        input: number;
        output: number;
        cache_read?: number;
        cache_write?: number;
    };
}
