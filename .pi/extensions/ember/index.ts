import { existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { Type, StringEnum } from "@earendil-works/pi-ai";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import {
	DEFAULT_MAX_BYTES,
	DEFAULT_MAX_LINES,
	formatSize,
	truncateHead,
	withFileMutationQueue,
	type TruncationResult,
} from "@earendil-works/pi-coding-agent";
import { Text } from "@earendil-works/pi-tui";

const DEFAULT_TIMEOUT_MS = 120_000;
const ARTIFACT_CONTEXT_BYTES = 16 * 1024;
const ARTIFACT_CONTEXT_LINES = 240;

type TextPart = { type: "text"; text: string };

interface EmberRunDetails {
	command: string;
	args: string[];
	cwd: string;
	code: number;
	stderr?: string;
	truncation?: TruncationResult;
	fullOutputPath?: string;
}

function stripAt(path: string): string {
	return path.startsWith("@") ? path.slice(1) : path;
}

function emberBin(cwd: string): string {
	if (process.env.EMBER_BIN) return process.env.EMBER_BIN;
	const local = resolve(cwd, "build/cli/ember");
	if (existsSync(local)) return local;
	return "ember";
}

function inputArgs(input: string, kind: "binary" | "regions" | undefined): string[] {
	const path = stripAt(input);
	if (kind === "regions") return ["--regions", path];
	return [path];
}

function looksHexAddress(value: string): boolean {
	return /^(?:0x)?[0-9a-fA-F]+$/.test(value.trim());
}

function safeName(value: string): string {
	return value.replace(/[^A-Za-z0-9_.-]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 80) || "output";
}

async function writeArtifact(cwd: string, hint: string, text: string): Promise<string> {
	const dir = resolve(cwd, ".pi", "ember-artifacts");
	await mkdir(dir, { recursive: true });
	const hash = createHash("sha256").update(text).digest("hex").slice(0, 12);
	const file = join(dir, `${Date.now()}-${safeName(hint)}-${hash}.txt`);
	await withFileMutationQueue(file, async () => {
		await writeFile(file, text, "utf8");
	});
	return file;
}

async function resolveAnnotationAddress(
	pi: ExtensionAPI,
	ctx: ExtensionContext,
	input: string,
	addrOrSymbol: string,
	signal?: AbortSignal,
	timeoutMs = DEFAULT_TIMEOUT_MS,
): Promise<string> {
	if (looksHexAddress(addrOrSymbol)) return addrOrSymbol;
	const command = emberBin(ctx.cwd);
	const result = await pi.exec(command, ["--validate", addrOrSymbol, "--json", stripAt(input)], { signal, timeout: timeoutMs });
	if ((result.code ?? 0) !== 0) {
		throw new Error(`ember --validate failed for ${addrOrSymbol}: ${result.stderr || result.stdout}`);
	}
	const parsed = JSON.parse(result.stdout || "{}");
	const resolved = parsed?.bound?.[0]?.addr;
	if (typeof resolved !== "string") {
		throw new Error(`ember --validate did not resolve ${addrOrSymbol}`);
	}
	return resolved;
}

async function formatOutput(text: string, opts?: { cwd?: string; hint?: string; artifactFirst?: boolean }): Promise<{
	content: TextPart[];
	truncation?: TruncationResult;
	fullOutputPath?: string;
}> {
	const artifactFirst = opts?.artifactFirst ?? true;
	const bytes = Buffer.byteLength(text, "utf8");
	if (artifactFirst && opts?.cwd && bytes > ARTIFACT_CONTEXT_BYTES) {
		const fullOutputPath = await writeArtifact(opts.cwd, opts.hint ?? "ember", text);
		const preview = truncateHead(text, {
			maxLines: ARTIFACT_CONTEXT_LINES,
			maxBytes: ARTIFACT_CONTEXT_BYTES,
		});
		let result = preview.content;
		result += `\n\n[Artifact-first: output is ${formatSize(bytes)} and was saved to ${fullOutputPath}.`;
		result += ` Showing only the first ${preview.outputLines} of ${preview.totalLines} lines to avoid RE context bloat.`;
		result += ` Use ember_artifact_read to inspect focused slices.]`;
		return {
			content: [{ type: "text", text: result }],
			truncation: preview.truncated ? preview : undefined,
			fullOutputPath,
		};
	}

	const truncation = truncateHead(text, {
		maxLines: DEFAULT_MAX_LINES,
		maxBytes: DEFAULT_MAX_BYTES,
	});

	let result = truncation.content;
	let fullOutputPath: string | undefined;
	if (truncation.truncated) {
		fullOutputPath = opts?.cwd
			? await writeArtifact(opts.cwd, opts.hint ?? "ember", text)
			: join(await mkdtemp(join(tmpdir(), "pi-ember-")), "output.txt");
		if (!opts?.cwd) {
			const path = fullOutputPath;
			await withFileMutationQueue(path, async () => {
				await writeFile(path, text, "utf8");
			});
		}
		result += `\n\n[Output truncated: showing ${truncation.outputLines} of ${truncation.totalLines} lines`;
		result += ` (${formatSize(truncation.outputBytes)} of ${formatSize(truncation.totalBytes)}).`;
		result += ` Full output saved to: ${fullOutputPath}]`;
	}
	return {
		content: [{ type: "text", text: result }],
		truncation: truncation.truncated ? truncation : undefined,
		fullOutputPath,
	};
}

async function runEmber(
	pi: ExtensionAPI,
	ctx: ExtensionContext,
	args: string[],
	signal?: AbortSignal,
	timeoutMs = DEFAULT_TIMEOUT_MS,
): Promise<{ content: TextPart[]; details: EmberRunDetails }> {
	const command = emberBin(ctx.cwd);
	const result = await pi.exec(command, args, { signal, timeout: timeoutMs });
	const stdout = result.stdout ?? "";
	const stderr = result.stderr ?? "";
	const prefix = `$ ${command} ${args.map((a) => (/[\s"']/.test(a) ? JSON.stringify(a) : a)).join(" ")}\n`;
	const combined = `${prefix}${stdout}${stderr ? `${stdout ? "\n" : ""}[stderr]\n${stderr}` : ""}`;
	const formatted = await formatOutput(combined.trimEnd() + "\n", {
		cwd: ctx.cwd,
		hint: args[0] ? `ember-${args[0]}-${basename(args[args.length - 1] ?? "output")}` : "ember",
	});
	const details: EmberRunDetails = {
		command,
		args,
		cwd: ctx.cwd,
		code: result.code ?? 0,
		stderr: stderr || undefined,
		truncation: formatted.truncation,
		fullOutputPath: formatted.fullOutputPath,
	};
	if ((result.code ?? 0) !== 0) {
		throw new Error(`ember exited ${result.code}: ${combined.slice(0, 4000)}`);
	}
	return { content: formatted.content, details };
}

const InputKind = StringEnum(["binary", "regions"] as const, {
	description: "Input type. Use regions for raw runtime memory manifests consumed by ember --regions.",
	default: "binary",
});

const ViewKind = StringEnum(["pseudo", "disasm", "cfg", "ir", "ssa", "struct"] as const, {
	description: "Code view to render for one function.",
	default: "pseudo",
});

const LookupKind = StringEnum([
	"containing_fn",
	"refs_to",
	"refs_to_loose",
	"callees",
	"explain_address",
	"state_map",
	"branch_on",
	"guard_map",
	"side_effects",
	"object_roles",
	"vtable_at",
	"dump_object",
	"disasm_at",
] as const);

const AccessKind = StringEnum(["read", "write", "lea", "code-ptr", "all"] as const);

export default function (pi: ExtensionAPI) {
	pi.on("session_start", (_event, ctx) => {
		if (ctx.hasUI) ctx.ui.setStatus("ember", `ember: ${emberBin(ctx.cwd)}`);
	});

	pi.on("before_agent_start", (event) => {
		let extra = "";
		if (existsSync(resolve(event.systemPromptOptions.cwd, "EMBER.md"))) {
			extra += "\n\nEmber extension: use ember_inventory for first contact, ember_code for targeted pseudo-C/disasm, ember_lookup for xrefs/state/vtable/address probes, and ember_annotate only for evidence-backed conclusions.";
		}
		if (!extra) return;
		return { systemPrompt: event.systemPrompt + extra };
	});

	pi.registerTool({
		name: "ember_inventory",
		label: "Ember Inventory",
		description: `Run cheap Ember inventory passes over a binary or --regions manifest. Output is truncated to ${DEFAULT_MAX_LINES} lines or ${formatSize(DEFAULT_MAX_BYTES)}; full output is saved if truncated.`,
		promptSnippet: "Inventory a binary with Ember functions, strings, identifiers, and basic headers.",
		promptGuidelines: [
			"Use ember_inventory before broad reverse-engineering questions; prefer functions/strings/identify before expensive pseudo-C sweeps.",
		],
		parameters: Type.Object({
			input: Type.String({ description: "Binary path, minidump path, or regions manifest path." }),
			inputKind: Type.Optional(InputKind),
			sections: Type.Optional(Type.Boolean({ description: "Run plain ember header/sections/import summary first.", default: false })),
			functions: Type.Optional(Type.Boolean({ description: "Include --functions." })),
			strings: Type.Optional(Type.Boolean({ description: "Include --strings." })),
			identify: Type.Optional(Type.Boolean({ description: "Include --identify crypto/protocol scan." })),
			json: Type.Optional(Type.Boolean({ description: "Request --json for commands that support it." })),
			rowLimit: Type.Optional(Type.Number({ description: "Cap broad list rows with --row-limit. Use 0 for all rows.", default: 2000 })),
			timeoutMs: Type.Optional(Type.Number({ description: "Command timeout in milliseconds." })),
		}),
		async execute(_id, params, signal, onUpdate, ctx) {
			const batches: string[] = [];
			const baseInput = inputArgs(params.input, params.inputKind);
			const sections = params.sections ?? false;
			const selected = sections || params.functions || params.strings || params.identify;
			const jobs: string[][] = [];
			const rowLimitArgs = params.rowLimit === undefined ? ["--row-limit", "2000"] : ["--row-limit", String(params.rowLimit)];
			if (!selected) jobs.push(["--functions", ...rowLimitArgs, ...(params.json ? ["--json"] : []), ...baseInput]);
			if (sections) jobs.push([...rowLimitArgs, ...baseInput]);
			if (params.functions) jobs.push(["--functions", ...rowLimitArgs, ...(params.json ? ["--json"] : []), ...baseInput]);
			if (params.strings) jobs.push(["--strings", ...(params.json ? ["--json"] : []), ...baseInput]);
			if (params.identify) jobs.push(["--identify", ...(params.json ? ["--json"] : []), ...baseInput]);
			for (const args of jobs) {
				onUpdate?.({ content: [{ type: "text", text: `Running ember ${args[0] ?? params.input}...` }], details: { args } });
				const result = await runEmber(pi, ctx, args, signal, params.timeoutMs);
				batches.push(result.content[0]?.text ?? "");
			}
			const formatted = await formatOutput(batches.join("\n---\n"), {
				cwd: ctx.cwd,
				hint: `ember-inventory-${basename(stripAt(params.input))}`,
			});
			return { content: formatted.content, details: { jobs, truncation: formatted.truncation, fullOutputPath: formatted.fullOutputPath } };
		},
		renderCall(args, theme) {
			return new Text(theme.fg("toolTitle", theme.bold("ember inventory ")) + theme.fg("accent", args.input ?? ""), 0, 0);
		},
	});

	pi.registerTool({
		name: "ember_code",
		label: "Ember Code",
		description: `Render one Ember function view (-p/-d/-c/-i/--ssa/--struct). Output is truncated to ${DEFAULT_MAX_LINES} lines or ${formatSize(DEFAULT_MAX_BYTES)}.`,
		promptSnippet: "Read one function from a binary as Ember pseudo-C, disassembly, CFG, or IR.",
		promptGuidelines: [
			"Use ember_code with view=pseudo and a specific function/address after anchoring with strings, xrefs, or containing_fn.",
			"Use ember_code ipa/resolveCalls/eh only when the richer facts change a naming, typing, or indirect-call decision.",
		],
		parameters: Type.Object({
			input: Type.String({ description: "Binary path, minidump path, or regions manifest path." }),
			inputKind: Type.Optional(InputKind),
			symbol: Type.String({ description: "Function name or address for -s/--symbol." }),
			view: Type.Optional(ViewKind),
			ipa: Type.Optional(Type.Boolean({ description: "Add --ipa before rendering." })),
			resolveCalls: Type.Optional(Type.Boolean({ description: "Add --resolve-calls." })),
			eh: Type.Optional(Type.Boolean({ description: "Add --eh." })),
			showProvenance: Type.Optional(Type.Boolean({ description: "Add --show-provenance for annotations." })),
			annotations: Type.Optional(Type.String({ description: "Annotation sidecar path." })),
			timeoutMs: Type.Optional(Type.Number()),
		}),
		async execute(_id, params, signal, _onUpdate, ctx) {
			const viewFlag = params.view === "disasm" ? "-d"
				: params.view === "cfg" ? "-c"
				: params.view === "ir" ? "-i"
				: params.view === "ssa" ? "--ssa"
				: params.view === "struct" ? "--struct"
				: "-p";
			const args = [viewFlag];
			if (params.ipa) args.push("--ipa");
			if (params.resolveCalls) args.push("--resolve-calls");
			if (params.eh) args.push("--eh");
			if (params.showProvenance) args.push("--show-provenance");
			if (params.annotations) args.push("--annotations", stripAt(params.annotations));
			args.push("-s", params.symbol, ...inputArgs(params.input, params.inputKind));
			return runEmber(pi, ctx, args, signal, params.timeoutMs);
		},
		renderCall(args, theme) {
			return new Text(theme.fg("toolTitle", theme.bold("ember code ")) + theme.fg("accent", args.symbol ?? "") + theme.fg("dim", ` ${args.view ?? "pseudo"}`), 0, 0);
		},
	});

	pi.registerTool({
		name: "ember_lookup",
		label: "Ember Lookup",
		description: `Run targeted Ember lookup/probe commands: refs, callees, state maps, object roles, vtables, address explanation, or disasm-at. Output is truncated to ${DEFAULT_MAX_LINES} lines or ${formatSize(DEFAULT_MAX_BYTES)}.`,
		promptSnippet: "Targeted Ember lookup for refs, callees, containing functions, state maps, vtables, objects, and address explanations.",
		promptGuidelines: [
			"Use ember_lookup for local evidence before whole-program heavy passes: containing_fn, refs_to, callees, explain_address, state_map, branch_on, and guard_map.",
		],
		parameters: Type.Object({
			input: Type.String({ description: "Binary path, minidump path, or regions manifest path." }),
			inputKind: Type.Optional(InputKind),
			kind: LookupKind,
			target: Type.String({ description: "VA, function name, or OBJ:OFF depending on lookup kind." }),
			json: Type.Optional(Type.Boolean({ description: "Add --json for commands that support it." })),
			access: Type.Optional(AccessKind),
			count: Type.Optional(Type.Number({ description: "Instruction count for disasm_at." })),
			size: Type.Optional(Type.Number({ description: "Object size for dump_object." })),
			limit: Type.Optional(Type.Number({ description: "Limit for vtable_at." })),
			timeoutMs: Type.Optional(Type.Number()),
		}),
		async execute(_id, params, signal, _onUpdate, ctx) {
			const flag = params.kind === "containing_fn" ? "--containing-fn"
				: params.kind === "refs_to" ? "--refs-to"
				: params.kind === "refs_to_loose" ? "--refs-to-loose"
				: params.kind === "callees" ? "--callees"
				: params.kind === "explain_address" ? "--explain-address"
				: params.kind === "state_map" ? "--state-map"
				: params.kind === "branch_on" ? "--branch-on"
				: params.kind === "guard_map" ? "--guard-map"
				: params.kind === "side_effects" ? "--side-effects"
				: params.kind === "object_roles" ? "--object-roles"
				: params.kind === "vtable_at" ? "--vtable-at"
				: params.kind === "dump_object" ? "--dump-object"
				: "--disasm-at";
			const args = [flag, params.target];
			if (params.json) args.push("--json");
			if (params.access) args.push("--access", params.access);
			if (params.count !== undefined) args.push("--count", String(params.count));
			if (params.size !== undefined) args.push("--size", String(params.size));
			if (params.limit !== undefined) args.push("--limit", String(params.limit));
			args.push(...inputArgs(params.input, params.inputKind));
			return runEmber(pi, ctx, args, signal, params.timeoutMs);
		},
		renderCall(args, theme) {
			return new Text(theme.fg("toolTitle", theme.bold("ember lookup ")) + theme.fg("accent", args.kind ?? "") + theme.fg("dim", ` ${args.target ?? ""}`), 0, 0);
		},
	});

	pi.registerTool({
		name: "ember_annotate",
		label: "Ember Annotate",
		description: "Persist one evidence-backed Ember annotation using --annotate. Supports rename, note, signature, confidence/source/evidence, dry-run, and explicit annotation sidecar.",
		promptSnippet: "Write one evidence-backed rename, note, or signature to Ember annotations.",
		promptGuidelines: [
			"Use ember_annotate only after citing concrete evidence from strings, callees, imports, constants, RTTI/vtables, control flow, recognized library matches, or runtime facts.",
			"Set ember_annotate confidence honestly; avoid promoting guesses as facts.",
		],
		parameters: Type.Object({
			input: Type.String({ description: "Binary path or minidump path. For --regions annotations, pass the sidecar with annotations." }),
			addr: Type.String({ description: "Address or function name to annotate. Names are resolved through ember --validate." }),
			name: Type.Optional(Type.String({ description: "Rename target." })),
			note: Type.Optional(Type.String({ description: "Free-form note." })),
			signature: Type.Optional(Type.String({ description: "Function signature." })),
			confidence: Type.Optional(Type.Number({ description: "0.0-1.0 confidence." })),
			source: Type.Optional(Type.String({ description: "Annotation source, default pi:ember-extension." })),
			evidence: Type.Optional(Type.String({ description: "Short evidence citation." })),
			annotations: Type.Optional(Type.String({ description: "Annotation sidecar path." })),
			dryRun: Type.Optional(Type.Boolean({ description: "Preview TSV without writing." })),
			timeoutMs: Type.Optional(Type.Number()),
		}),
		async execute(_id, params, signal, _onUpdate, ctx) {
			const resolvedAddr = await resolveAnnotationAddress(pi, ctx, params.input, params.addr, signal, params.timeoutMs);
			const args = ["--annotate", resolvedAddr];
			if (params.name) args.push("--set-name", params.name);
			if (params.note) args.push("--set-note", params.note);
			if (params.signature) args.push("--set-signature", params.signature);
			if (params.confidence !== undefined) args.push("--confidence", String(params.confidence));
			args.push("--source", params.source ?? "pi:ember-extension");
			if (params.evidence) args.push("--evidence", params.evidence);
			if (params.annotations) args.push("--annotations", stripAt(params.annotations));
			if (params.dryRun) args.push("--dry-run");
			args.push(stripAt(params.input));
			return runEmber(pi, ctx, args, signal, params.timeoutMs);
		},
		renderCall(args, theme) {
			const what = args.name ?? args.signature ?? args.note ?? "annotation";
			return new Text(theme.fg("toolTitle", theme.bold("ember annotate ")) + theme.fg("accent", args.addr ?? "") + theme.fg("dim", ` ${what}`), 0, 0);
		},
	});

	pi.registerTool({
		name: "ember_artifact_read",
		label: "Ember Artifact Read",
		description: "Read focused slices from large Ember artifact files produced by artifact-first tool output. Supports line offset/limit and substring filtering.",
		promptSnippet: "Read focused slices from saved Ember artifacts instead of bloating context with whole RE outputs.",
		promptGuidelines: [
			"Use ember_artifact_read when an Ember tool reports an artifact path; inspect only the needed lines or filter text.",
		],
		parameters: Type.Object({
			path: Type.String({ description: "Artifact file path returned by an Ember tool." }),
			offset: Type.Optional(Type.Number({ description: "1-indexed line offset, default 1." })),
			limit: Type.Optional(Type.Number({ description: "Maximum matching/output lines, default 200." })),
			filter: Type.Optional(Type.String({ description: "Optional case-insensitive substring filter." })),
		}),
		async execute(_id, params, _signal, _onUpdate, ctx) {
			const artifactPath = resolve(ctx.cwd, stripAt(params.path));
			const root = resolve(ctx.cwd, ".pi", "ember-artifacts");
			if (!artifactPath.startsWith(root)) {
				throw new Error(`artifact path must be under ${root}`);
			}
			const text = await readFile(artifactPath, "utf8");
			const all = text.split(/\r?\n/);
			const offset = Math.max(1, Math.floor(params.offset ?? 1));
			const limit = Math.max(1, Math.min(2000, Math.floor(params.limit ?? 200)));
			const filter = params.filter?.toLowerCase();
			const rows: string[] = [];
			for (let i = offset - 1; i < all.length && rows.length < limit; ++i) {
				const line = all[i] ?? "";
				if (filter && !line.toLowerCase().includes(filter)) continue;
				rows.push(`${i + 1}: ${line}`);
			}
			const body = rows.join("\n") || "No artifact lines matched.";
			const formatted = await formatOutput(body + "\n", { cwd: ctx.cwd, hint: `artifact-read-${basename(artifactPath)}`, artifactFirst: false });
			return { content: formatted.content, details: { path: artifactPath, totalLines: all.length, offset, limit, filter } };
		},
		renderCall(args, theme) {
			return new Text(theme.fg("toolTitle", theme.bold("ember artifact ")) + theme.fg("accent", args.path ?? ""), 0, 0);
		},
	});

	pi.registerTool({
		name: "ember_cli",
		label: "Ember CLI",
		description: `Run an Ember CLI command for advanced/long-tail flags not covered by specialized tools. Pass flags as argv entries, not a shell string. Output is truncated to ${DEFAULT_MAX_LINES} lines or ${formatSize(DEFAULT_MAX_BYTES)}.`,
		promptSnippet: "Run advanced Ember CLI flags not covered by specialized tools.",
		promptGuidelines: [
			"Use ember_cli only for Ember features not covered by ember_inventory, ember_lookup, ember_code, ember_annotate, ember_apply, ember_recognize, or ember_python.",
			"Pass ember_cli args as separate argv strings; do not include shell quoting or a full command line.",
		],
		parameters: Type.Object({
			args: Type.Array(Type.String(), { description: "Ember arguments before the input path, e.g. ['--list-annotations', '--json']." }),
			input: Type.Optional(Type.String({ description: "Optional binary/minidump/raw-region manifest path appended after args." })),
			inputKind: Type.Optional(InputKind),
			timeoutMs: Type.Optional(Type.Number({ description: "Command timeout in milliseconds." })),
		}),
		async execute(_id, params, signal, _onUpdate, ctx) {
			const args = [...params.args];
			if (params.input) args.push(...inputArgs(params.input, params.inputKind));
			return runEmber(pi, ctx, args, signal, params.timeoutMs);
		},
		renderCall(args, theme) {
			return new Text(theme.fg("toolTitle", theme.bold("ember cli ")) + theme.fg("dim", (args.args ?? []).join(" ")), 0, 0);
		},
	});

	pi.registerTool({
		name: "ember_apply",
		label: "Ember Apply",
		description: "Apply or dry-run a declarative .ember script/cache annotations file against a binary. Supports explicit annotation sidecar.",
		promptSnippet: "Apply or dry-run .ember annotation scripts.",
		promptGuidelines: [
			"Use ember_apply with dryRun=true before bulk annotation writes unless the user explicitly asked to apply known-good annotations.",
		],
		parameters: Type.Object({
			input: Type.String({ description: "Binary, minidump, or raw-region manifest path." }),
			inputKind: Type.Optional(InputKind),
			script: Type.String({ description: ".ember script or annotations cache/db path to apply." }),
			annotations: Type.Optional(Type.String({ description: "Annotation sidecar path to write/read." })),
			dryRun: Type.Optional(Type.Boolean({ description: "Preview annotation TSV without writing." })),
			timeoutMs: Type.Optional(Type.Number()),
		}),
		async execute(_id, params, signal, _onUpdate, ctx) {
			const args = ["--apply", stripAt(params.script)];
			if (params.annotations) args.push("--annotations", stripAt(params.annotations));
			if (params.dryRun) args.push("--dry-run");
			args.push(...inputArgs(params.input, params.inputKind));
			return runEmber(pi, ctx, args, signal, params.timeoutMs);
		},
		renderCall(args, theme) {
			return new Text(theme.fg("toolTitle", theme.bold("ember apply ")) + theme.fg("accent", args.script ?? ""), 0, 0);
		},
	});

	pi.registerTool({
		name: "ember_recognize",
		label: "Ember Recognize",
		description: `Run Ember fingerprint/TEEF/recognition workflows. Output is truncated to ${DEFAULT_MAX_LINES} lines or ${formatSize(DEFAULT_MAX_BYTES)}.`,
		promptSnippet: "Run TEEF corpus build, library recognition, fingerprints, diff, and identify workflows.",
		promptGuidelines: [
			"Use ember_recognize mode=identify for crypto/protocol scans, mode=teef to build a corpus, mode=recognize to match a binary against corpus TSVs, and mode=fingerprints for cross-version matching.",
		],
		parameters: Type.Object({
			input: Type.String({ description: "Binary path." }),
			mode: StringEnum(["identify", "teef", "recognize", "fingerprints", "diff"] as const),
			corpus: Type.Optional(Type.Array(Type.String(), { description: "Corpus TSV path(s) for recognize." })),
			old: Type.Optional(Type.String({ description: "OLD binary path for diff mode; input is the NEW binary." })),
			fingerprintOld: Type.Optional(Type.String({ description: "OLD-side fingerprints TSV for diff mode." })),
			fingerprintNew: Type.Optional(Type.String({ description: "NEW-side fingerprints TSV for diff mode." })),
			fingerprintOut: Type.Optional(Type.String({ description: "Write fingerprints TSV to this path." })),
			json: Type.Optional(Type.Boolean({ description: "Add --json where supported; for diff, uses --diff-format json." })),
			module: Type.Optional(Type.String({ description: "Optional module/scope argument for supported commands." })),
			teefNoL4: Type.Optional(Type.Boolean({ description: "With mode=teef, add --teef-no-l4." })),
			l0Prefilter: Type.Optional(Type.Boolean({ description: "With mode=recognize, add --l0-prefilter." })),
			timeoutMs: Type.Optional(Type.Number()),
		}),
		async execute(_id, params, signal, _onUpdate, ctx) {
			const args: string[] = [];
			if (params.mode === "identify") args.push("--identify");
			else if (params.mode === "teef") {
				args.push("--teef");
				if (params.teefNoL4) args.push("--teef-no-l4");
			} else if (params.mode === "recognize") {
				args.push("--recognize");
				for (const c of params.corpus ?? []) args.push("--corpus", stripAt(c));
				if (params.l0Prefilter) args.push("--l0-prefilter");
			} else if (params.mode === "fingerprints") args.push("--fingerprints");
			else {
				if (!params.old && !params.fingerprintOld) throw new Error("ember_recognize diff mode requires old or fingerprintOld");
				args.push("--diff", stripAt(params.old ?? params.input));
				if (params.fingerprintOld) args.push("--fingerprint-old", stripAt(params.fingerprintOld));
				if (params.fingerprintNew) args.push("--fingerprint-new", stripAt(params.fingerprintNew));
				if (params.json) args.push("--diff-format", "json");
			}
			if (params.mode !== "diff" && params.json) args.push("--json");
			if (params.fingerprintOut) args.push("--fingerprint-out", stripAt(params.fingerprintOut));
			if (params.module) args.push("--module", params.module);
			args.push(stripAt(params.input));
			return runEmber(pi, ctx, args, signal, params.timeoutMs);
		},
		renderCall(args, theme) {
			return new Text(theme.fg("toolTitle", theme.bold("ember recognize ")) + theme.fg("accent", args.mode ?? ""), 0, 0);
		},
	});

	pi.registerTool({
		name: "ember_python",
		label: "Ember Python",
		description: `Run a short Python snippet with the in-repo emberpy wrapper preloaded as Ember/e. Use for wrapper-only workflows such as investigate(), explain_path(), or annotate_batch(). Output is truncated to ${DEFAULT_MAX_LINES} lines or ${formatSize(DEFAULT_MAX_BYTES)}.`,
		promptSnippet: "Run emberpy Python wrapper snippets for batched/high-level Ember workflows.",
		promptGuidelines: [
			"Use ember_python when the Python wrapper's function handles, investigate(), explain_path(), or annotate_batch() are a better fit than one CLI probe.",
			"Keep ember_python snippets short and deterministic; prefer ember_inventory/ember_lookup/ember_code for simple one-command probes.",
		],
		parameters: Type.Object({
			input: Type.Optional(Type.String({ description: "Binary path. If provided, e = Ember(input, ...) is preloaded." })),
			script: Type.String({ description: "Python body to run. Ember, EmberError, and e (when input is set) are preloaded." }),
			timeoutMs: Type.Optional(Type.Number({ description: "Command timeout in milliseconds." })),
		}),
		async execute(_id, params, signal, _onUpdate, ctx) {
			const dir = await mkdtemp(join(tmpdir(), "pi-emberpy-"));
			const file = join(dir, "snippet.py");
			const input = params.input ? JSON.stringify(stripAt(params.input)) : "None";
			const prelude = [
				"import json, os, sys",
				`sys.path.insert(0, ${JSON.stringify(resolve(ctx.cwd, "python"))})`,
				`os.environ.setdefault('EMBER_BIN', ${JSON.stringify(emberBin(ctx.cwd))})`,
				"from emberpy import Ember, EmberError",
				`e = Ember(${input}, cwd=${JSON.stringify(ctx.cwd)}) if ${input} is not None else None`,
				"def dump(obj):",
				"    print(json.dumps(obj, indent=2, sort_keys=True) if not isinstance(obj, str) else obj)",
				"",
			].join("\n");
			await withFileMutationQueue(file, async () => {
				await writeFile(file, `${prelude}${params.script}\n`, "utf8");
			});
			const result = await pi.exec("python3", [file], { signal, timeout: params.timeoutMs ?? DEFAULT_TIMEOUT_MS });
			const stdout = result.stdout ?? "";
			const stderr = result.stderr ?? "";
			const combined = `$ python3 ${file}\n${stdout}${stderr ? `${stdout ? "\n" : ""}[stderr]\n${stderr}` : ""}`;
			const formatted = await formatOutput(combined.trimEnd() + "\n", {
				cwd: ctx.cwd,
				hint: `ember-python-${basename(params.input ? stripAt(params.input) : "snippet")}`,
			});
			if ((result.code ?? 0) !== 0) {
				throw new Error(`ember_python exited ${result.code}: ${combined.slice(0, 4000)}`);
			}
			return { content: formatted.content, details: { file, code: result.code ?? 0, truncation: formatted.truncation, fullOutputPath: formatted.fullOutputPath } };
		},
		renderCall(args, theme) {
			return new Text(theme.fg("toolTitle", theme.bold("ember python ")) + theme.fg("accent", args.input ?? "snippet"), 0, 0);
		},
	});

	pi.registerCommand("ember", {
		description: "Show Ember extension status and tool workflow",
		handler: async (_args, ctx) => {
			ctx.ui.notify(`Ember extension loaded (${emberBin(ctx.cwd)})`, "info");
			ctx.ui.setEditorText("Use ember_inventory on the target, then ember_lookup to anchor evidence, ember_code for one function, and ember_annotate for evidence-backed conclusions.");
		},
	});
}
