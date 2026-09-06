import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { endpoints, ConfigSearchResult, ConfigSearchDeviceMatch } from "../api";
import { PageHeader, Loading, EmptyState, StatCard } from "../components/ui";

const EXAMPLES = ["telnet", "snmp community public", "ip http server", "password 0"];

export default function ConfigSearch() {
  const [query, setQuery] = useState("");
  const [result, setResult] = useState<ConfigSearchResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useState<"all" | "compliant" | "non_compliant" | "unscanned">("all");
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  function runSearch(q: string, deep: boolean) {
    if (!q.trim()) {
      setResult(null);
      return;
    }
    setLoading(true);
    endpoints
      .configSearch(q.trim(), deep)
      .then((r) => setResult(r.data))
      .finally(() => setLoading(false));
  }

  // Fast structured-only search as the user types; a deeper raw-config
  // grep fires once they pause, so results don't jump around mid-keystroke.
  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    if (!query.trim()) {
      setResult(null);
      return;
    }
    runSearch(query, false);
    debounceRef.current = setTimeout(() => runSearch(query, true), 450);
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query]);

  const devices = result?.devices ?? [];
  const filtered = devices.filter((d) => {
    if (filter === "compliant") return d.compliant === true;
    if (filter === "non_compliant") return d.compliant === false;
    if (filter === "unscanned") return d.compliant === null;
    return true;
  });

  return (
    <div>
      <PageHeader
        title="Config Search"
        subtitle="Search the fleet's latest configs and compliance findings — see who's affected and whether it's already flagged."
      />
      <div className="px-8 pb-8 space-y-5">
        <div className="card space-y-3">
          <input
            autoFocus
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder='Search a term or phrase, e.g. "telnet" or "snmp community public"'
            className="w-full bg-slate-900 border border-soc-border rounded-lg px-4 py-3 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:ring-1 focus:ring-cyan-600"
          />
          <div className="flex items-center gap-2 flex-wrap text-xs text-slate-500">
            <span>Try:</span>
            {EXAMPLES.map((ex) => (
              <button
                key={ex}
                onClick={() => setQuery(ex)}
                className="px-2 py-1 rounded-md bg-slate-800/60 hover:bg-slate-800 text-slate-300 font-mono"
              >
                {ex}
              </button>
            ))}
            {loading && <span className="ml-auto text-cyan-500">Searching…</span>}
          </div>
        </div>

        {!query.trim() && (
          <EmptyState message="Enter a term above — e.g. a protocol name, a default credential string, or a raw config fragment — to see every affected device." />
        )}

        {query.trim() && result && (
          <>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <StatCard label="Devices matched" value={result.total_matches} />
              <StatCard label="Compliant" value={result.compliant_count} tone="good" />
              <StatCard label="Non-compliant" value={result.non_compliant_count} tone="critical" />
              <StatCard label="Not yet scanned" value={result.unscanned_count} tone="default" />
            </div>

            {result.raw_config_search_truncated && (
              <div className="text-xs text-amber-400">
                Fleet is large — the raw-config pass was capped; structured compliance-finding matches are still complete.
              </div>
            )}

            <div className="flex items-center gap-2 text-xs">
              {(
                [
                  ["all", `All (${devices.length})`],
                  ["compliant", `Compliant (${result.compliant_count})`],
                  ["non_compliant", `Non-compliant (${result.non_compliant_count})`],
                  ["unscanned", `Not scanned (${result.unscanned_count})`],
                ] as const
              ).map(([key, label]) => (
                <button
                  key={key}
                  onClick={() => setFilter(key)}
                  className={`px-3 py-1.5 rounded-full border ${
                    filter === key
                      ? "border-cyan-700 bg-cyan-950/60 text-cyan-300"
                      : "border-soc-border text-slate-400 hover:text-slate-200"
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>

            <div className="space-y-3">
              {filtered.length === 0 && <EmptyState message="No devices match this filter." />}
              {filtered.map((d) => (
                <DeviceMatchRow key={d.device_id} match={d} query={result.query} />
              ))}
            </div>
          </>
        )}

        {query.trim() && loading && !result && <Loading />}
      </div>
    </div>
  );
}

function DeviceMatchRow({ match, query }: { match: ConfigSearchDeviceMatch; query: string }) {
  const complianceLabel =
    match.compliant === true ? "COMPLIANT" : match.compliant === false ? "NON-COMPLIANT" : "NOT SCANNED";
  const complianceClass =
    match.compliant === true ? "badge-pass" : match.compliant === false ? "badge-fail" : "badge-na";

  return (
    <div className="card">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div className="min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <Link className="font-semibold text-slate-100 hover:text-cyan-400" to={`/devices/${match.device_id}`}>
              {match.hostname || match.device_id}
            </Link>
            {match.vendor && <span className="text-xs text-slate-500">{match.vendor}</span>}
            <span className={`badge ${complianceClass}`}>{complianceLabel}</span>
            {match.final_decision && <span className="text-xs text-slate-500">({match.final_decision})</span>}
          </div>
          {match.matched_controls.length > 0 && (
            <div className="text-xs text-amber-400 mt-1">
              Matched controls: {match.matched_controls.join(", ")}
            </div>
          )}
          {match.context_lines.length > 0 && (
            <div className="mt-2 space-y-1">
              {match.context_lines.slice(0, 3).map((line, i) => (
                <div key={i} className="font-mono text-xs text-slate-400 bg-slate-900/60 rounded px-2 py-1 truncate">
                  {highlight(line, query)}
                </div>
              ))}
            </div>
          )}
          {match.scan_id && (
            <div className="text-xs text-slate-600 mt-1">
              <Link className="text-cyan-500 hover:underline" to={`/scans/${match.scan_id}`}>
                view scan {match.scan_id}
              </Link>
            </div>
          )}
        </div>
        <div className="text-xs text-slate-500 shrink-0 text-right">
          <div>{match.match_count} match{match.match_count === 1 ? "" : "es"}</div>
          <div className="text-slate-600">{match.match_source.replace("_", " ")}</div>
        </div>
      </div>
    </div>
  );
}

function highlight(text: string, query: string) {
  if (!query) return text;
  const idx = text.toLowerCase().indexOf(query.toLowerCase());
  if (idx === -1) return text;
  return (
    <>
      {text.slice(0, idx)}
      <span className="text-cyan-400">{text.slice(idx, idx + query.length)}</span>
      {text.slice(idx + query.length)}
    </>
  );
}