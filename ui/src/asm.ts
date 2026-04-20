// Minimal x86-64 assembler, scoped to what an RE workflow patches with.
// Lives in TS so the patch dialog can re-encode per keystroke without a
// CLI subprocess; the C++ side has no assembler today (it only owns
// the disassembler direction).
//
// Supported, by category:
//   no-operand  : nop, ret, int3, ud2, hlt, cld, std, clc, stc, leave
//   stack       : push r64, pop r64
//   data move   : mov r64, imm   |  mov r32, imm   |  mov r, r
//   arith r,r   : xor / and / or / add / sub  (encoded as r/m64, r64)
//   branches    : jmp <abs>      |  jcc <abs>     |  call <abs>
//
// Branches take an absolute target address; the assembler resolves
// to rel8 / rel32 against the line's address (computed from `vaddr`
// passed to `assemble` plus the bytes already emitted on prior lines
// of the same input). Multi-line input is supported; comments after
// `;` or `//` are stripped.
//
// Out of scope (call site convention if you need them later): SIB,
// memory operands, ModR/M with displacement, sub-32-bit registers,
// SSE/AVX, label resolution. Unsupported input returns an error
// rather than encoding wrong bytes silently.

export type AsmLine = { bytes: number[]; line: number; src: string };
export type AsmError = { error: string; line: number; src: string };
export type AsmResult = {
  ok:    AsmLine[];
  errs:  AsmError[];
  bytes: number[];      // concatenated; may be partial when errs is non-empty
};

// 64-bit GPR names → encoding (low 3 bits go in modrm/opcode, high bit
// goes in REX.B / REX.R). Aliases not duplicated — write one canonical
// name per slot.
const REG64: Record<string, number> = {
  rax: 0, rcx: 1, rdx: 2, rbx: 3, rsp: 4, rbp: 5, rsi: 6, rdi: 7,
  r8:  8, r9:  9, r10:10, r11:11, r12:12, r13:13, r14:14, r15:15,
};
const REG32: Record<string, number> = {
  eax: 0, ecx: 1, edx: 2, ebx: 3, esp: 4, ebp: 5, esi: 6, edi: 7,
  r8d: 8, r9d: 9, r10d:10, r11d:11, r12d:12, r13d:13, r14d:14, r15d:15,
};
type RegSize = 32 | 64;
type Reg = { id: number; size: RegSize };

function lookupReg(s: string): Reg | null {
  const k = s.toLowerCase();
  if (k in REG64) return { id: REG64[k], size: 64 };
  if (k in REG32) return { id: REG32[k], size: 32 };
  return null;
}

// Numeric literal: hex (0x...), decimal, or signed (-).
function parseImm(s: string): bigint | null {
  const t = s.trim();
  if (!t) return null;
  try {
    if (/^-?0x[0-9a-fA-F]+$/.test(t)) return BigInt(t);
    if (/^-?\d+$/.test(t))            return BigInt(t);
  } catch { /* fall through */ }
  return null;
}

function rex(w: 0 | 1, r: 0 | 1, x: 0 | 1, b: 0 | 1): number | null {
  if (w | r | x | b) return 0x40 | (w << 3) | (r << 2) | (x << 1) | b;
  return null;
}

function modRM(mod: number, reg: number, rm: number): number {
  return ((mod & 3) << 6) | ((reg & 7) << 3) | (rm & 7);
}

function le(value: bigint, width: number): number[] {
  const out: number[] = [];
  let v = BigInt.asUintN(width * 8, value);
  for (let i = 0; i < width; i++) {
    out.push(Number(v & 0xffn));
    v >>= 8n;
  }
  return out;
}

// -- encoders ---------------------------------------------------------

function encNoOperand(mnem: string): number[] | null {
  switch (mnem) {
    case "nop":   return [0x90];
    case "ret":   return [0xc3];
    case "int3":  return [0xcc];
    case "ud2":   return [0x0f, 0x0b];
    case "hlt":   return [0xf4];
    case "cld":   return [0xfc];
    case "std":   return [0xfd];
    case "clc":   return [0xf8];
    case "stc":   return [0xf9];
    case "leave": return [0xc9];
    default:      return null;
  }
}

function encPushPop(mnem: "push" | "pop", reg: Reg): number[] | string {
  if (reg.size !== 64) return `${mnem} requires a 64-bit register`;
  const opcode = (mnem === "push" ? 0x50 : 0x58) + (reg.id & 7);
  const r = rex(0, 0, 0, reg.id >= 8 ? 1 : 0);
  return r === null ? [opcode] : [r, opcode];
}

function encMovImm(dst: Reg, imm: bigint): number[] | string {
  // mov r64, imm64  →  REX.W + B8+r io
  // mov r32, imm32  →  [REX.B?] + B8+r id
  if (dst.size === 64) {
    const r = rex(1, 0, 0, dst.id >= 8 ? 1 : 0)!;
    return [r, 0xb8 + (dst.id & 7), ...le(imm, 8)];
  }
  // 32-bit. Imm range check.
  const lo = -(1n << 31n), hi = (1n << 32n) - 1n;
  if (imm < lo || imm > hi) return `imm out of range for ${dst.size}-bit operand`;
  const r = rex(0, 0, 0, dst.id >= 8 ? 1 : 0);
  const head = r === null ? [] : [r];
  return [...head, 0xb8 + (dst.id & 7), ...le(imm, 4)];
}

function encMovRR(dst: Reg, src: Reg): number[] | string {
  if (dst.size !== src.size) return "mov r,r operand sizes must match";
  const w: 0 | 1 = dst.size === 64 ? 1 : 0;
  // 89 /r  : mov r/m, r  (we route through this form)
  const r = rex(w, src.id >= 8 ? 1 : 0, 0, dst.id >= 8 ? 1 : 0);
  const head = r === null ? [] : [r];
  return [...head, 0x89, modRM(0b11, src.id, dst.id)];
}

function encArithRR(opcode: number, dst: Reg, src: Reg): number[] | string {
  if (dst.size !== src.size) return "operand sizes must match";
  const w: 0 | 1 = dst.size === 64 ? 1 : 0;
  const r = rex(w, src.id >= 8 ? 1 : 0, 0, dst.id >= 8 ? 1 : 0);
  const head = r === null ? [] : [r];
  return [...head, opcode, modRM(0b11, src.id, dst.id)];
}

const CC: Record<string, number> = {
  jo:  0x0, jno: 0x1,
  jb:  0x2, jc:  0x2, jnae:0x2,
  jnb: 0x3, jnc: 0x3, jae: 0x3,
  je:  0x4, jz:  0x4,
  jne: 0x5, jnz: 0x5,
  jbe: 0x6, jna: 0x6,
  ja:  0x7, jnbe:0x7,
  js:  0x8, jns: 0x9,
  jp:  0xa, jpe: 0xa, jnp: 0xb, jpo: 0xb,
  jl:  0xc, jnge:0xc, jge: 0xd, jnl: 0xd,
  jle: 0xe, jng: 0xe, jg:  0xf, jnle:0xf,
};

function encJmpAbs(target: bigint, here: bigint): number[] | string {
  // Try short (eb) first, fall back to near (e9).
  const short = target - (here + 2n);
  if (short >= -128n && short <= 127n) {
    return [0xeb, ...le(short, 1)];
  }
  const near = target - (here + 5n);
  if (near < -(1n << 31n) || near > (1n << 31n) - 1n) {
    return `jmp target too far (need rel32)`;
  }
  return [0xe9, ...le(near, 4)];
}

function encJccAbs(cc: number, target: bigint, here: bigint): number[] | string {
  const short = target - (here + 2n);
  if (short >= -128n && short <= 127n) {
    return [0x70 + cc, ...le(short, 1)];
  }
  const near = target - (here + 6n);
  if (near < -(1n << 31n) || near > (1n << 31n) - 1n) {
    return `jcc target too far`;
  }
  return [0x0f, 0x80 + cc, ...le(near, 4)];
}

function encCallAbs(target: bigint, here: bigint): number[] | string {
  const off = target - (here + 5n);
  if (off < -(1n << 31n) || off > (1n << 31n) - 1n) {
    return `call target too far (need indirect)`;
  }
  return [0xe8, ...le(off, 4)];
}

// -- line-level entry -------------------------------------------------

function tokenizeOperands(s: string): string[] {
  return s.split(",").map(t => t.trim()).filter(Boolean);
}

function encodeLine(src: string, here: bigint): number[] | string {
  const stripped = src.replace(/(;|\/\/).*$/, "").trim();
  if (!stripped) return [];

  // Split mnemonic from operand tail.
  const m = /^([A-Za-z][A-Za-z0-9]*)(?:\s+(.*))?$/.exec(stripped);
  if (!m) return `unparseable line`;
  const mnem = m[1].toLowerCase();
  const operands = m[2] ? tokenizeOperands(m[2]) : [];

  // No-operand instructions.
  if (operands.length === 0) {
    const bytes = encNoOperand(mnem);
    if (bytes) return bytes;
    return `${mnem}: missing operands or unknown instruction`;
  }

  // Branches — single absolute address operand.
  if (mnem === "jmp" && operands.length === 1) {
    const t = parseImm(operands[0]);
    if (t === null) return `jmp target must be a numeric address`;
    return encJmpAbs(t, here);
  }
  if (mnem === "call" && operands.length === 1) {
    const t = parseImm(operands[0]);
    if (t === null) return `call target must be a numeric address`;
    return encCallAbs(t, here);
  }
  if (mnem in CC && operands.length === 1) {
    const t = parseImm(operands[0]);
    if (t === null) return `${mnem} target must be a numeric address`;
    return encJccAbs(CC[mnem], t, here);
  }

  // Stack.
  if ((mnem === "push" || mnem === "pop") && operands.length === 1) {
    const r = lookupReg(operands[0]);
    if (!r) return `${mnem}: ${operands[0]} is not a register`;
    return encPushPop(mnem, r);
  }

  // Two-operand: mov / xor / and / or / add / sub.
  if (operands.length === 2) {
    const dst = lookupReg(operands[0]);
    if (!dst) return `${operands[0]} is not a register`;
    const srcImm = parseImm(operands[1]);
    const srcReg = lookupReg(operands[1]);

    if (mnem === "mov") {
      if (srcReg) return encMovRR(dst, srcReg);
      if (srcImm !== null) return encMovImm(dst, srcImm);
      return `mov: ${operands[1]} is not a register or immediate`;
    }
    const arith: Record<string, number> = {
      // /r form, op encoded as r/m, r → opcodes 0x01/0x09/0x21/0x29/0x31
      add: 0x01, or: 0x09, and: 0x21, sub: 0x29, xor: 0x31,
    };
    if (mnem in arith) {
      if (!srcReg) return `${mnem} reg, reg only — immediates not supported yet`;
      return encArithRR(arith[mnem], dst, srcReg);
    }
  }

  return `unsupported instruction: ${mnem}`;
}

// Public entry point. `vaddr` is the address the first byte will land
// at; subsequent lines start at `vaddr + (bytes emitted so far)`.
export function assemble(text: string, vaddr: number | bigint): AsmResult {
  const lines = text.split("\n");
  const ok:   AsmLine[]  = [];
  const errs: AsmError[] = [];
  let here = typeof vaddr === "bigint" ? vaddr : BigInt(vaddr);

  for (let i = 0; i < lines.length; i++) {
    const src = lines[i];
    const r = encodeLine(src, here);
    if (typeof r === "string") {
      errs.push({ error: r, line: i, src });
      continue;
    }
    if (r.length === 0) continue;
    ok.push({ bytes: r, line: i, src });
    here += BigInt(r.length);
  }

  const bytes: number[] = [];
  for (const l of ok) bytes.push(...l.bytes);
  return { ok, errs, bytes };
}

// Render bytes as space-separated uppercase hex pairs, the form the
// patch sidecar / dialog uses.
export function bytesToHex(bytes: number[]): string {
  return bytes.map(b => b.toString(16).padStart(2, "0").toUpperCase()).join("");
}
