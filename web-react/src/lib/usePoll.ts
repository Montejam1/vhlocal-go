import { useEffect, useRef, useState } from "react";

/** Fetch on mount and re-fetch every `ms` (default 4s). Returns the latest value
 *  and a manual refresh. Stops when `ms` is 0/undefined (fetch once). */
export function usePoll<T>(fn: () => Promise<T>, ms = 4000): { data: T | null; error: string | null; refresh: () => void } {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const fnRef = useRef(fn);
  fnRef.current = fn;

  const run = () =>
    fnRef
      .current()
      .then((d) => {
        setData(d);
        setError(null);
      })
      .catch((e) => setError(String(e?.message || e)));

  useEffect(() => {
    run();
    if (!ms) return;
    const t = setInterval(run, ms);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ms]);

  return { data, error, refresh: run };
}
