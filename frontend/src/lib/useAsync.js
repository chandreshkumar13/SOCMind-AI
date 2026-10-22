import { useCallback, useEffect, useRef, useState } from 'react';

/** Loads data with explicit loading / error / data state. `reload()` refetches; stale responses are ignored. */
export default function useAsync(fn, deps = []) {
  const [state, setState] = useState({ loading: true, error: null, data: null });
  const latest = useRef(0);

  const reload = useCallback(async () => {
    const id = ++latest.current;
    setState((s) => ({ ...s, loading: true, error: null }));
    try {
      const data = await fn();
      if (id === latest.current) setState({ loading: false, error: null, data });
    } catch (err) {
      if (id === latest.current) setState((s) => ({ loading: false, error: err.message || 'Request failed', data: s.data }));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  useEffect(() => {
    reload();
  }, [reload]);

  return { ...state, reload };
}
