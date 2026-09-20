import { useEffect, useRef, useState } from "react";
import { ChangeRequest, PushPlan, ReviewEvent, endpoints } from "../api";
import { Chip, errText, verdictTone } from "./DeploymentPipeline";

// ---------------------------------------------------------------------------
// Human-in-the-loop UI for a change request: an approval that is bound to the
// revision the reviewer actually saw, demands a written reason when the change
// is risky or BLOCKed, and explains *why* a control is locked instead of just
// greying it out. Plus the append-only trail of every human decision.
// ---------------------------------------------------------------------------

const fmt = (v?: string | null) => (v ? new Date(v.endsWith("Z") ? v : v + "Z").toLocaleString() : "—");

export function ApprovalPanel({ cr, canApprove, currentUser, onDone, onStale }: {
  cr: ChangeRequest;
  canApprove: boolean;
  currentUser: string | null;
  onDone: () => void;
  /** Called when the server says the change moved under the reviewer. */
  onStale: () => void;
}) {
  const hitl = cr.hitl;
  const [mode, setMode] = useState<"idle" | "approve" | "reject">("idle");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [stale, setStale] = useState(false);

  // If the change is edited while the panel is open, throw away a half-typed
  // decision made against the old revision.
  const seenRevision = useRef(cr.revision ?? 1);
  useEffect(() => {
    if ((cr.revision ?? 1) !== seenRevision.current) {
      seenRevision.current = cr.revision ?? 1;
      setMode("idle");
      setNote("");
    }
  }, [cr.revision]);

  const override = !!hitl?.override_required;
  const noteRequired = !!hitl?.note_required;
  const minChars = hitl?.min_note_chars ?? 10;
  const selfAuthored = !!hitl?.four_eyes_required && !!cr.created_by && cr.created_by === currentUser;

  async function submit() {
    setBusy(true);
    setErr(null);
    try {
      if (mode === "approve") {
        await endpoints.approveChangeRequest(cr.id, {
          comment: note.trim() || undefined,
          revision: cr.revision ?? 1,
          proposed_config_hash: cr.proposed_config_hash,
        });
      } else {
        await endpoints.rejectChangeRequest(cr.id, note.trim());
      }
      setMode("idle");
      setNote("");
      onDone();
    } catch (e: any) {
      const code = e?.response?.data?.detail?.code;
      if (code === "stale_revision") {
        setStale(true);
        onStale();
      }
      setErr(errText(e, "Could not record your decision."));
    } finally {
      setBusy(false);
    }
  }

  if (!canApprove) {
    return (
      <div className="ui-callout ui-tone-idle text-sm font-medium">
        🔒 Read-only: only a Security Analyst or Admin can approve or reject this change.
      </div>
    );
  }

  const approveDisabled = busy || (noteRequired && note.trim().length < minChars);
  const rejectDisabled = busy || note.trim().length < 3;

  return (
    <div className="space-y-3">
      <div className="ui-callout ui-tone-info text-sm">
        <span className="ui-callout-body">
          AI synthesised this syntax; it cannot be deployed until a human approves it. Your approval applies to
          <strong> revision {cr.revision ?? 1}</strong> (<span className="ui-mono">{cr.proposed_config_hash.slice(0, 12)}</span>) only —
          if the proposal is edited afterwards it has to be approved again.
        </span>
      </div>

      {override && (
        <div className="ui-callout ui-tone-bad text-sm space-y-1">
          <div className="font-bold">The validator BLOCKED this change</div>
          <div className="ui-callout-body">
            {cr.final_reason || "OPA / Batfish / risk scoring recommended blocking it."} You can still approve it, but that is an
            explicit override and your written justification is stored on the record and in the audit log.
          </div>
        </div>
      )}
      {!override && noteRequired && (
        <div className="ui-callout ui-tone-warn text-sm ui-callout-body">
          This change is flagged {cr.final_decision === "REVIEW" ? "for review" : ""}
          {cr.risk_level && ["HIGH", "CRITICAL"].includes(cr.risk_level) ? ` (risk ${cr.risk_level})` : ""} — a reviewer note is required to approve it.
        </div>
      )}
      {hitl?.four_eyes_required && (
        <div className={`ui-callout ${selfAuthored ? "ui-tone-bad" : "ui-tone-info"} text-sm ui-callout-body`}>
          {selfAuthored
            ? `Four-eyes rule: you created this request, so a different reviewer has to approve it. You can still reject it.`
            : `Four-eyes rule is on for this change: the author (${cr.created_by || "unknown"}) cannot approve it.`}
        </div>
      )}
      {stale && (
        <div className="ui-callout ui-tone-warn text-sm font-medium">
          This change moved while you were reviewing it. The latest revision has been reloaded — read it again before deciding.
        </div>
      )}

      {mode === "idle" ? (
        <div className="flex gap-2 flex-wrap">
          <button className="ui-btn ui-btn-approve" onClick={() => { setMode("approve"); setErr(null); }} disabled={selfAuthored}
            title={selfAuthored ? "Four-eyes rule: the author cannot approve" : undefined}>
            {override ? "Approve (override)…" : "Approve…"}
          </button>
          <button className="ui-btn ui-btn-reject" onClick={() => { setMode("reject"); setErr(null); }}>Reject…</button>
        </div>
      ) : (
        <div className="space-y-2">
          <label className="ui-label block" htmlFor={`note-${cr.id}`}>
            {mode === "reject"
              ? "Reason for rejecting (required)"
              : override
                ? `Justification for overriding the BLOCK (required, min ${minChars} characters)`
                : noteRequired
                  ? `Reviewer note (required, min ${minChars} characters)`
                  : "Reviewer note (optional)"}
          </label>
          <textarea id={`note-${cr.id}`} className="ui-field" rows={3} value={note} autoFocus
            onChange={(e) => setNote(e.target.value)}
            placeholder={mode === "reject" ? "e.g. Outside the change window / wrong VLAN" : "What did you check? e.g. ticket reference, diff reviewed, Batfish delta understood"} />
          <div className="flex items-center gap-2 flex-wrap">
            {mode === "approve" ? (
              <button className="ui-btn ui-btn-approve" disabled={approveDisabled} onClick={submit}>
                {busy ? "Recording…" : override ? "Confirm override & approve" : "Confirm approval"}
              </button>
            ) : (
              <button className="ui-btn ui-btn-danger" disabled={rejectDisabled} onClick={submit}>
                {busy ? "Recording…" : "Confirm rejection"}
              </button>
            )}
            <button className="ui-btn ui-btn-neutral" disabled={busy} onClick={() => { setMode("idle"); setErr(null); }}>Cancel</button>
            {mode === "approve" && noteRequired && (
              <span className="text-xs ui-muted">{Math.min(note.trim().length, minChars)}/{minChars}</span>
            )}
          </div>
        </div>
      )}
      {err && <div className="text-sm font-medium" role="alert" style={{ color: "var(--bad-fg)" }}>{err}</div>}
    </div>
  );
}

// ---------------------------------------------------------------- decision
export function DecisionSummary({ cr }: { cr: ChangeRequest }) {
  const hitl = cr.hitl;
  if (cr.status === "REJECTED") {
    return (
      <div className="ui-callout ui-tone-bad text-sm space-y-0.5">
        <div className="font-bold">Rejected by {cr.rejected_by || "—"} · {fmt(cr.rejected_at)}</div>
        {cr.rejection_reason && <div className="ui-callout-body">{cr.rejection_reason}</div>}
      </div>
    );
  }
  if (cr.approved_by && ["APPROVED", "DEPLOYING", "DEPLOYED", "FAILED"].includes(cr.status)) {
    const override = !!cr.override_justification;
    return (
      <div className={`ui-callout ${override ? "ui-tone-warn" : "ui-tone-ok"} text-sm space-y-0.5`}>
        <div className="font-bold">
          {override ? "Approved as an override of the validator's BLOCK" : "Approved"} by {cr.approved_by} · {fmt(cr.approved_at)}
          {cr.approved_revision ? ` · revision ${cr.approved_revision}` : ""}
        </div>
        {cr.review_comment && <div className="ui-callout-body">“{cr.review_comment}”</div>}
        {hitl?.approval_expires_at && cr.status === "APPROVED" && (
          <div className="ui-callout-body">Approval expires {fmt(hitl.approval_expires_at)}.</div>
        )}
      </div>
    );
  }
  return null;
}

// ------------------------------------------------------------------- trail
const ACTION: Record<string, { label: string; tone: "ok" | "bad" | "warn" | "info" | "idle" }> = {
  submitted: { label: "Submitted & validated", tone: "info" },
  edited: { label: "Proposal edited", tone: "warn" },
  approved: { label: "Approved", tone: "ok" },
  override_approved: { label: "Approved (override of BLOCK)", tone: "warn" },
  rejected: { label: "Rejected", tone: "bad" },
  deployed: { label: "Deployed", tone: "ok" },
  deploy_failed: { label: "Deployment failed", tone: "bad" },
  rolled_back: { label: "Rolled back", tone: "ok" },
  rollback_failed: { label: "Rollback failed", tone: "bad" },
};

export function ReviewTrail({ events }: { events: ReviewEvent[] | undefined }) {
  const list = [...(events || [])].reverse();
  if (list.length === 0) {
    return <div className="text-sm ui-muted">No human decisions have been recorded on this change yet.</div>;
  }
  return (
    <ol className="space-y-2">
      {list.map((e, i) => {
        const meta = ACTION[e.action] || { label: e.action, tone: "idle" as const };
        return (
          <li key={i} className="ui-inset px-3 py-2 text-sm flex gap-3 items-start">
            <span className="w-[210px] shrink-0"><Chip tone={meta.tone}>{meta.label}</Chip></span>
            <div className="min-w-0 flex-1">
              <div className="ui-text">
                <strong>{e.actor}</strong> <span className="ui-muted">· {fmt(e.at)}{e.revision ? ` · rev ${e.revision}` : ""}</span>
              </div>
              {e.comment && <div className="ui-muted break-words">{String(e.comment)}</div>}
            </div>
          </li>
        );
      })}
    </ol>
  );
}

// ------------------------------------------------------------ deploy dialog
export function DeployDialog({ cr, transports, defaultTransport, onCancel, onConfirm }: {
  cr: ChangeRequest;
  transports: { value: string; label: string }[];
  defaultTransport: string;
  onCancel: () => void;
  onConfirm: (transport: string) => void;
}) {
  const [transport, setTransport] = useState(defaultTransport);
  const [plan, setPlan] = useState<PushPlan | null>(null);
  const [ack, setAck] = useState(false);

  useEffect(() => {
    let live = true;
    endpoints.changeRequestDeployPlan(cr.id).then((r) => live && setPlan(r.data)).catch(() => live && setPlan(null));
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onCancel();
    window.addEventListener("keydown", onKey);
    return () => { live = false; window.removeEventListener("keydown", onKey); };
  }, [cr.id, onCancel]);

  const unsafe = plan !== null && !plan.safe;
  const risky = cr.final_decision !== "PASS" || ["HIGH", "CRITICAL"].includes(cr.risk_level || "");

  return (
    <div className="fixed inset-0 z-[110] flex items-center justify-center px-4" style={{ background: "rgba(10,14,24,.55)" }}>
      <div role="dialog" aria-modal="true" aria-labelledby="deploy-dialog-title"
        className="card w-full max-w-2xl space-y-4 shadow-2xl max-h-[90vh] overflow-y-auto">
        <div>
          <h2 id="deploy-dialog-title" className="text-lg font-bold ui-text">Deploy to device?</h2>
          <p className="text-sm ui-muted">This pushes real commands to the device. Nothing else runs until you confirm.</p>
        </div>

        <div className="flex gap-2 flex-wrap items-center text-sm">
          <span className="ui-muted">device</span><span className="ui-mono ui-text">{cr.device_id}</span>
          <Chip tone={verdictTone(cr.final_decision)}>Decision {cr.final_decision || "—"}</Chip>
          <Chip tone={verdictTone(cr.risk_level)}>Risk {cr.risk_level || "—"}</Chip>
          <span className="ui-muted">approved by</span><strong className="ui-text">{cr.approved_by || "—"}</strong>
        </div>

        {cr.override_justification && (
          <div className="ui-callout ui-tone-warn text-sm ui-callout-body">
            Approved as an override of the validator's BLOCK: “{cr.override_justification}”
          </div>
        )}

        <div>
          <div className="ui-label mb-1">Commands that will be pushed{plan ? ` (${plan.commands.length})` : ""}</div>
          {plan === null ? <div className="text-sm ui-muted">Working out deploy commands…</div>
            : unsafe ? <div className="ui-callout ui-tone-bad text-sm">No safe minimal command set could be derived — deployment will be refused. Edit the proposal first.</div>
              : <pre className="ui-code max-h-56">{plan.commands.join("\n")}</pre>}
          {(plan?.warnings || []).map((w, i) => <div key={i} className="text-sm mt-1" style={{ color: "var(--warn-fg)" }}>{w}</div>)}
        </div>

        <div>
          <label className="ui-label block mb-1" htmlFor="deploy-transport">Transport</label>
          <select id="deploy-transport" className="ui-field max-w-xs" value={transport} onChange={(e) => setTransport(e.target.value)}>
            {transports.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
          </select>
        </div>

        <label className="flex gap-2 items-start text-sm ui-text cursor-pointer">
          <input type="checkbox" className="mt-1" checked={ack} onChange={(e) => setAck(e.target.checked)} />
          <span>
            I have reviewed the commands above{risky ? ", including the validator's warnings," : ""} and understand they will be applied to the device now.
            The device is re-checked against the validated baseline first and the change is verified afterwards.
          </span>
        </label>

        <div className="flex justify-end gap-2">
          <button className="ui-btn ui-btn-neutral" onClick={onCancel}>Cancel</button>
          <button className="ui-btn ui-btn-deploy" disabled={!ack || unsafe || plan === null} onClick={() => onConfirm(transport)}>
            Deploy now
          </button>
        </div>
      </div>
    </div>
  );
}
