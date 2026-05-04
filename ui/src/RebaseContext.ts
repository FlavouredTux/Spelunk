import { createContext, useContext, useMemo } from "react";
import { rebaseDisplayAddr } from "./api";

// Rebase context: provides a function to remap absolute VAs into the
// user's chosen display base.  Every component that shows an address
// should use `fmtAddr(n)` instead of `"0x" + n.toString(16)`.

export type RebaseFn = (addr: number) => number;

const RebaseCtx = createContext<RebaseFn>((n) => n);

export const RebaseProvider = RebaseCtx.Provider;

/** Hook: returns a function that rebases an absolute VA into the display base. */
export function useRebase(): RebaseFn {
  return useContext(RebaseCtx);
}

/** Hook: returns a function that formats a rebased address as "0x1234". */
export function useFmtAddr(): (addr: number) => string {
  const rebase = useRebase();
  return useMemo(() => {
    return (addr: number) => "0x" + rebase(addr).toString(16);
  }, [rebase]);
}

/** Build the rebase function from the binary's preferred load base and the user setting. */
export function makeRebaseFn(binaryBase: string, userBase: string): RebaseFn {
  const base = parseInt(binaryBase, 16) || 0;
  const target = parseInt(userBase, 16) || 0;
  const offset = target - base;
  if (offset === 0) return (n) => n;  // fast path: no rebase needed
  return (n) => n + offset;
}
