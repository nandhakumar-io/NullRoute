import React, { createContext, useCallback, useContext, useState } from "react";

interface ConfirmOptions {
  title?: string;
  /** Main message body. Supports plain text only. */
  message: string;
  confirmLabel?: string;
  cancelLabel?: string;
  /** Renders the confirm button in red for destructive actions (default: true). */
  danger?: boolean;
}

type ConfirmFn = (message: string, options?: Omit<ConfirmOptions, "message">) => Promise<boolean>;

const ConfirmContext = createContext<ConfirmFn | undefined>(undefined);

interface PendingConfirm extends ConfirmOptions {
  resolve: (value: boolean) => void;
}

export function ConfirmProvider({ children }: { children: React.ReactNode }) {
  const [pending, setPending] = useState<PendingConfirm | null>(null);

  const confirmFn = useCallback<ConfirmFn>((message, options) => {
    return new Promise<boolean>((resolve) => {
      setPending({ message, danger: true, ...options, resolve });
    });
  }, []);

  const settle = (value: boolean) => {
    pending?.resolve(value);
    setPending(null);
  };

  return (
    <ConfirmContext.Provider value={confirmFn}>
      {children}
      {pending && (
        <div
          className="fixed inset-0 z-[110] flex items-center justify-center bg-black/40 backdrop-blur-[1px] px-4"
          onKeyDown={(e) => {
            if (e.key === "Escape") settle(false);
          }}
        >
          <div
            role="alertdialog"
            aria-modal="true"
            aria-labelledby="confirm-dialog-title"
            className="w-full max-w-sm rounded-2xl border border-soc-border bg-soc-panel shadow-2xl shadow-black/40 p-5 animate-toast-in"
          >
            <h2 id="confirm-dialog-title" className="text-sm font-semibold text-slate-100">
              {pending.title || (pending.danger ? "Confirm action" : "Confirm")}
            </h2>
            <p className="mt-2 text-sm text-slate-400 leading-relaxed whitespace-pre-line">{pending.message}</p>
            <div className="mt-5 flex justify-end gap-2">
              <button
                autoFocus
                onClick={() => settle(false)}
                className="px-3 py-1.5 rounded-lg text-sm font-medium text-slate-300 hover:bg-slate-800/5 transition-colors"
              >
                {pending.cancelLabel || "Cancel"}
              </button>
              <button
                onClick={() => settle(true)}
                className={`px-3 py-1.5 rounded-lg text-sm font-medium text-white transition-colors ${
                  pending.danger ? "bg-red-600 hover:bg-red-700" : "bg-cyan-600 hover:bg-cyan-500"
                }`}
              >
                {pending.confirmLabel || (pending.danger ? "Delete" : "Confirm")}
              </button>
            </div>
          </div>
        </div>
      )}
    </ConfirmContext.Provider>
  );
}

/**
 * Promise-based replacement for window.confirm(). Await it inside an async
 * handler exactly like the native call: `if (!(await confirm("..."))) return;`
 * Unlike window.confirm, this doesn't block the JS event loop, can be styled
 * to match the app, and isn't silently suppressed by browser popup blockers.
 */
export function useConfirm(): ConfirmFn {
  const ctx = useContext(ConfirmContext);
  if (!ctx) throw new Error("useConfirm must be used within a ConfirmProvider");
  return ctx;
}