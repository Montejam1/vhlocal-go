import { useEffect, useRef, useState } from "react";

/** Fetch on mount and re-fetch every `ms` (default 4s). Returns the latest value,
 *  the last error, and a `loading` flag that is true only until the first settle —
 *  so callers can tell loading, empty-success, and error apart (feature 007, US1).
 *  Stops when `ms` is 0/undefined (fetch once). */
export function usePoll<T>(
  fn: () => Promise<T>,
  ms = 4000,
): { data: T | null; error: string | null; loading: boolean; refresh: () => void } {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const fnRef = useRef(fn);
  fnRef.current = fn;

  const run = () =>
    fnRef
      .current()
      .then((d) => {
        setData(d);
        setError(null);
      })
      .catch((e) => setError(String(e?.message || e)))
      .finally(() => setLoading(false));

  useEffect(() => {
    run();
    if (!ms) return;
    const t = setInterval(run, ms);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ms]);

  return { data, error, loading, refresh: run };
}
