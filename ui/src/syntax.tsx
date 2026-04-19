import type { JSX } from "react";
import { SH } from "./theme";

type Token = {
  text: string;
  color?: string;
  className?: string;
  onClick?: () => void;
  onContextMenu?: (ev: React.MouseEvent) => void;
  bold?: boolean;
};

const C_KEYWORDS = new Set([
  "if", "else", "while", "for", "do", "return", "break", "continue",
  "switch", "case", "default", "goto", "void", "sizeof", "struct",
  "union", "enum", "typedef", "static", "const", "volatile", "extern",
  "inline", "bool", "true", "false",
]);
const C_TYPES = new Set([
  "u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64", "char",
  "int", "short", "long", "unsigned", "signed", "float", "double", "size_t",
]);
const X86_REGS = new Set([
  "rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp","rip",
  "r8","r9","r10","r11","r12","r13","r14","r15",
  "eax","ebx","ecx","edx","esi","edi","ebp","esp",
  "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d",
  "ax","bx","cx","dx","si","di","bp","sp",
  "r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w",
  "al","bl","cl","dl","ah","bh","ch","dh",
  "spl","bpl","sil","dil",
  "r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b",
  "fs","gs","cs","ds","es","ss",
]);
const FLAGS = new Set(["zf", "sf", "cf", "of", "pf", "af"]);

const X86_TERMS = new Set([
  "ret", "jmp", "call", "hlt", "ud2", "int3", "syscall", "nop", "endbr64", "endbr32",
  "leave", "cdqe", "cdq", "cqo",
  "push", "pop",
  "mov", "movzx", "movsx", "movsxd", "lea", "xchg",
  "add", "sub", "adc", "sbb", "inc", "dec", "neg", "mul", "imul", "div", "idiv",
  "and", "or", "xor", "not", "shl", "shr", "sar", "rol", "ror",
  "cmp", "test",
  "je", "jne", "jz", "jnz", "jl", "jge", "jle", "jg",
  "jb", "jae", "jbe", "ja", "jo", "jno", "js", "jns", "jp", "jnp",
]);

export function highlightLine(
  line: string,
  onXref: (addr: number) => void,
  fnAddrByName?: Map<string, number>,
  onFnContext?: (addr: number, ev: React.MouseEvent) => void,
): JSX.Element[] {
  const tokens: Token[] = [];
  const len = line.length;
  let i = 0;

  const pushStr = (text: string, opts: Partial<Token> = {}) => {
    if (text) tokens.push({ text, ...opts });
  };

  while (i < len) {
    const ch = line[i];

    // comment //
    if (ch === "/" && line[i + 1] === "/") {
      pushStr(line.substring(i), { color: SH.comment });
      break;
    }
    // comment ;
    if (ch === ";" && (i === 0 || /\s/.test(line[i - 1]))) {
      pushStr(line.substring(i), { color: SH.comment });
      break;
    }
    // string
    if (ch === '"') {
      let j = i + 1;
      while (j < len && line[j] !== '"') {
        if (line[j] === "\\") j++;
        j++;
      }
      pushStr(line.substring(i, Math.min(j + 1, len)), { color: SH.string });
      i = Math.min(j + 1, len);
      continue;
    }
    // hex
    if (ch === "0" && (line[i + 1] === "x" || line[i + 1] === "X")) {
      const m = /^0[xX][0-9a-fA-F]+/.exec(line.substring(i));
      if (m) {
        pushStr(m[0], { color: SH.number });
        i += m[0].length;
        continue;
      }
    }
    // decimal
    if (ch >= "0" && ch <= "9") {
      const m = /^\d+/.exec(line.substring(i));
      if (m) {
        pushStr(m[0], { color: SH.number });
        i += m[0].length;
        continue;
      }
    }
    // identifier
    if (/[A-Za-z_]/.test(ch)) {
      const m = /^[A-Za-z_][\w]*/.exec(line.substring(i));
      if (m) {
        const word = m[0];
        const lower = word.toLowerCase();
        const next = line[i + word.length];

        // cross-ref: sub_<hex>
        const xref = /^sub_([0-9a-fA-F]+)$/.exec(word);
        if (xref) {
          const addr = parseInt(xref[1], 16);
          tokens.push({
            text: word,
            color: SH.xref,
            bold: true,
            onClick: () => onXref(addr),
            onContextMenu: onFnContext ? (ev) => onFnContext(addr, ev) : undefined,
            className: "sub-link",
          });
        }
        else if (lower === "bb" || /^bb_[0-9a-f]+$/.test(lower)) {
          pushStr(word, { color: SH.label });
        }
        else if (/^local_[0-9a-f]+$/.test(lower) || /^arg_[0-9a-f]+$/.test(lower)) {
          pushStr(word, { color: SH.reg });
        }
        // Function params injected by the emitter when no user signature
        // is present. `a1`, `a2`, ... bound in the function header.
        else if (/^a\d+$/.test(word)) {
          pushStr(word, { color: SH.arg });
        }
        // Call-return locals introduced by the emitter's rax-aliasing fix.
        // Shape: r_<callee-name>, optionally with a _<n> disambiguator.
        else if (/^r_[A-Za-z_]\w*$/.test(word)) {
          pushStr(word, { color: SH.bound });
        }
        else if (C_KEYWORDS.has(word)) {
          pushStr(word, { color: SH.keyword, bold: true });
        }
        else if (C_TYPES.has(word)) {
          pushStr(word, { color: SH.type });
        }
        else if (X86_REGS.has(lower)) {
          pushStr(word, { color: SH.reg });
        }
        else if (FLAGS.has(lower)) {
          pushStr(word, { color: SH.flag });
        }
        else if (X86_TERMS.has(lower)) {
          pushStr(word, { color: SH.keyword, bold: true });
        }
        else {
          const fnAddr = fnAddrByName?.get(word);
          if (fnAddr !== undefined) {
            tokens.push({
              text: word,
              color: SH.func,
              onClick: () => onXref(fnAddr),
              onContextMenu: onFnContext ? (ev) => onFnContext(fnAddr, ev) : undefined,
              className: "fn-link",
            });
          } else if (next === "(") {
            pushStr(word, { color: SH.func });
          } else {
            pushStr(word);
          }
        }
        i += word.length;
        continue;
      }
    }
    // operators / punctuation — render as-is but dimmed
    if (/[+\-*\/%<>=!&|^~?:,;{}\[\]().]/.test(ch)) {
      let j = i;
      while (j < len && /[+\-*\/%<>=!&|^~?:,;.]/.test(line[j])) j++;
      if (j > i) {
        pushStr(line.substring(i, j), { color: SH.op });
        i = j;
        continue;
      }
      pushStr(ch);
      i++;
      continue;
    }
    // default
    pushStr(ch);
    i++;
  }

  return tokens.map((t, k) => {
    const style: React.CSSProperties = {};
    if (t.color) style.color = t.color;
    if (t.bold) style.fontWeight = 600;
    if (t.onClick || t.onContextMenu) {
      style.cursor = "pointer";
      style.borderBottom = `1px dashed ${t.color || "currentColor"}`;
    }
    return (
      <span
        key={k}
        style={style}
        onClick={t.onClick}
        onContextMenu={t.onContextMenu}
      >
        {t.text}
      </span>
    );
  });
}
