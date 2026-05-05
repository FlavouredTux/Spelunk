import { createContext, useContext, useMemo } from "react";

export type RebaseFn = (addr: number) => number;

const RebaseCtx = createContext<RebaseFn>((n) => n);

export const RebaseProvider = RebaseCtx.Provider;

export function useRebase(): RebaseFn {
  return useContext(RebaseCtx);
}

export function useFmtAddr(): (addr: number) => string {
  const rebase = useRebase();
  return useMemo(() => (addr: number) => "0x" + rebase(addr).toString(16), [rebase]);
}

export function makeRebaseFn(binaryBase: string, userBase: string): RebaseFn {
  const base = parseInt(binaryBase, 16) || 0;
  const target = parseInt(userBase, 16) || 0;
  const offset = target - base;
  if (offset === 0) return (n) => n;
  return (n) => n + offset;
}
