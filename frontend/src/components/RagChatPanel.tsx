import { useRef, useState, useEffect, FormEvent } from "react";
import { endpoints, RagSource } from "../api";

type ChatMessage = {
  id: string;
  role: "user" | "assistant";
  text: string;
  sources?: RagSource[];
};

/**
 * Floating chat dock, bottom-right. Collapses to a small round launcher
 * button and expands into a full chat panel -- this is the "shrinkable"
 * RAG surface the dashboard docks alongside its metrics.
 *
 * Talks to /api/rag/query today, which runs a keyword-based retriever
 * over indexed findings/devices/Batfish results (see
 * backend/app/services/rag_service.py). Swapping in a real embeddings +
 * LLM pipeline later needs no changes here -- the response shape
 * (answer + cited sources) already matches what a generated answer would
 * return.
 */
export default function RagChatPanel() {
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [reindexing, setReindexing] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [messages, loading]);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    const question = input.trim();
    if (!question || loading) return;
    setInput("");
    const userMsg: ChatMessage = { id: `u-${Date.now()}`, role: "user", text: question };
    setMessages((m) => [...m, userMsg]);
    setLoading(true);
    try {
      const res = await endpoints.ragQuery(question);
      setMessages((m) => [
        ...m,
        { id: res.data.query_id, role: "assistant", text: res.data.answer, sources: res.data.sources },
      ]);
    } catch {
      setMessages((m) => [
        ...m,
        { id: `err-${Date.now()}`, role: "assistant", text: "Sorry, the RAG service didn't respond. Try again in a moment." },
      ]);
    } finally {
      setLoading(false);
    }
  }

  async function handleReindex() {
    setReindexing(true);
    try {
      const res = await endpoints.ragReindex();
      const counts = res.data.reindexed;
      const summary = Object.entries(counts).map(([k, v]) => `${v} ${k}`).join(", ");
      setMessages((m) => [
        ...m,
        { id: `sys-${Date.now()}`, role: "assistant", text: `Corpus refreshed: ${summary}.` },
      ]);
    } catch {
      setMessages((m) => [...m, { id: `err-${Date.now()}`, role: "assistant", text: "Reindex failed." }]);
    } finally {
      setReindexing(false);
    }
  }

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        className="fixed bottom-6 right-6 z-40 flex items-center gap-2 bg-cyan-600 hover:bg-cyan-500 text-white font-medium pl-4 pr-5 py-3 rounded-full shadow-lg shadow-cyan-900/30 transition-all hover:scale-[1.03]"
        title="Ask NetSecAuditor (RAG chat)"
      >
        <ChatIcon />
        <span className="text-sm">Ask NetSecAuditor</span>
      </button>
    );
  }

  return (
    <div className="fixed bottom-6 right-6 z-40 w-[380px] max-w-[calc(100vw-2rem)] h-[560px] max-h-[calc(100vh-4rem)] bg-soc-panel border border-soc-border rounded-2xl shadow-2xl shadow-black/30 flex flex-col overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-soc-border bg-slate-900/40">
        <div className="flex items-center gap-2 min-w-0">
          <div className="w-7 h-7 rounded-lg bg-cyan-600/15 text-cyan-400 flex items-center justify-center shrink-0">
            <ChatIcon size={15} />
          </div>
          <div className="min-w-0">
            <div className="text-sm font-semibold text-slate-200 truncate">Ask NetSecAuditor</div>
            <div className="text-[10px] text-slate-500 truncate">RAG over your compliance data · beta</div>
          </div>
        </div>
        <div className="flex items-center gap-1 shrink-0">
          <button
            onClick={handleReindex}
            disabled={reindexing}
            title="Refresh indexed data (findings, devices, Batfish results)"
            className="w-7 h-7 flex items-center justify-center rounded-md text-slate-500 hover:text-slate-200 hover:bg-slate-700/50 transition-colors disabled:opacity-40"
          >
            <RefreshIcon spinning={reindexing} />
          </button>
          <button
            onClick={() => setOpen(false)}
            title="Shrink"
            className="w-7 h-7 flex items-center justify-center rounded-md text-slate-500 hover:text-slate-200 hover:bg-slate-700/50 transition-colors"
          >
            <MinusIcon />
          </button>
        </div>
      </div>

      {/* Messages */}
      <div ref={scrollRef} className="flex-1 overflow-y-auto px-4 py-4 space-y-3">
        {messages.length === 0 && (
          <div className="text-center text-slate-500 text-xs px-4 py-8">
            Ask about open findings, a device's compliance history, or a network group's Batfish results.
            <div className="mt-3 flex flex-col gap-1.5 items-stretch">
              {["What are our current critical findings?", "Which devices have never been scanned?", "Any failing Batfish checks right now?"].map((q) => (
                <button
                  key={q}
                  onClick={() => setInput(q)}
                  className="text-left text-[11px] px-3 py-2 rounded-lg bg-slate-800/40 border border-soc-border hover:border-cyan-800 text-slate-400 hover:text-slate-200 transition-colors"
                >
                  {q}
                </button>
              ))}
            </div>
          </div>
        )}
        {messages.map((m) => (
          <div key={m.id} className={`flex ${m.role === "user" ? "justify-end" : "justify-start"}`}>
            <div
              className={`max-w-[85%] rounded-xl px-3 py-2 text-sm whitespace-pre-wrap ${
                m.role === "user"
                  ? "bg-cyan-600 text-white rounded-br-sm"
                  : "bg-slate-800/60 border border-soc-border text-slate-200 rounded-bl-sm"
              }`}
            >
              {m.text}
              {m.sources && m.sources.length > 0 && (
                <div className="mt-2 pt-2 border-t border-slate-700/60 flex flex-wrap gap-1">
                  {m.sources.map((s) => (
                    <span
                      key={s.document_id}
                      title={s.content}
                      className="text-[10px] px-1.5 py-0.5 rounded bg-slate-900/60 border border-slate-700 text-slate-400"
                    >
                      {s.source_type}: {s.title.slice(0, 24)}{s.title.length > 24 ? "…" : ""}
                    </span>
                  ))}
                </div>
              )}
            </div>
          </div>
        ))}
        {loading && (
          <div className="flex justify-start">
            <div className="bg-slate-800/60 border border-soc-border rounded-xl rounded-bl-sm px-3 py-2 text-sm text-slate-400">
              Searching compliance data…
            </div>
          </div>
        )}
      </div>

      {/* Input */}
      <form onSubmit={handleSubmit} className="flex items-center gap-2 px-3 py-3 border-t border-soc-border">
        <input
          className="input flex-1"
          placeholder="Ask a question…"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          disabled={loading}
        />
        <button type="submit" disabled={loading || !input.trim()} className="btn-primary px-3 py-1.5 disabled:opacity-40">
          <SendIcon />
        </button>
      </form>
    </div>
  );
}

function ChatIcon({ size = 18 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z" />
    </svg>
  );
}
function MinusIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
      <line x1="5" y1="12" x2="19" y2="12" />
    </svg>
  );
}
function SendIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <line x1="22" y1="2" x2="11" y2="13" />
      <polygon points="22 2 15 22 11 13 2 9 22 2" />
    </svg>
  );
}
function RefreshIcon({ spinning }: { spinning?: boolean }) {
  return (
    <svg
      width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"
      strokeLinecap="round" strokeLinejoin="round"
      style={spinning ? { animation: "spin 0.8s linear infinite" } : undefined}
    >
      <polyline points="23 4 23 10 17 10" />
      <polyline points="1 20 1 14 7 14" />
      <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
    </svg>
  );
}
