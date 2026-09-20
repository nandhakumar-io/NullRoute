import { useState } from "react";
import { Link } from "react-router-dom";
import {
  DeploymentRecord, PipelineStage, PostValidation, RollbackRecord, StageStatus, endpoints,
} from "../api";
import BatfishDeltaView from "./BatfishDeltaView";

// ---------------------------------------------------------------------------
// Deployment pipeline view: shows the auditor exactly which step a deployment
// (or rollback) stopped at -- connection, pre-check, commit, verification,
// post-validation -- instead of a single status word and an error string.
// ---------------------------------------------------------------------------

export function errText(e: any, fallback: string): string {
  const d = e?.response?.data?.detail;
  if (!d) return fallback;
  if (typeof d === "string") return d;
  if (typeof d?.message === "string") return d.message;
  return fallback;
}

type Tone = "ok" | "bad" | "warn" | "info" | "idle";

const STAGE_TONE: Record<StageStatus, Tone> = {
  passed: "ok", failed: "bad", warning: "warn", running: "info", pending: "idle", skipped: "idle",
};
const STAGE_WORD: Record<StageStatus, string> = {
  passed: "Passed", failed: "Failed", warning: "Warning", running: "Running", pending: "Pending", skipped: "Skipped",
};
const STAGE_GLYPH: Record<StageStatus, string> = {
  passed: "✓", failed: "✕", warning: "!", running: "…", pending: "", skipped: "–",
};

export function Chip({ tone, children, title }: { tone: Tone; children: React.ReactNode; title?: string }) {
  return <span className={`ui-chip ui-tone-${tone}`} title={title}>{children}</span>;
}

/** Deployment / CR / scan verdict words -> tone. */
export function verdictTone(v?: string | null): Tone {
  if (!v) return "idle";
  const u = v.toUpperCase();
  if (["PASS", "BATFISH_PASS", "LOW", "APPROVED", "VERIFIED", "DEPLOYED", "ROLLED_BACK", "OK"].includes(u)) return "ok";
  if (["BLOCK", "FAIL", "BATFISH_FAIL", "BATFISH_ERROR", "HIGH", "CRITICAL", "FAILED", "DRIFTED", "REJECTED",
    "ABORTED_STALE_HASH", "CRITICAL_MANUAL_INTERVENTION_REQUIRED"].includes(u)) return "bad";
  if (["REVIEW", "MEDIUM", "PENDING_APPROVAL", "PENDING_VALIDATION", "DEPLOYING", "PENDING"].includes(u)) return "warn";
  return "idle";
}

const fmt = (v?: string | null) => (v ? new Date(v.endsWith("Z") ? v : v + "Z").toLocaleString() : null);
const short = (h?: string | null) => (h ? h.slice(0, 12) : "—");

function durationOf(s: PipelineStage): string | null {
  if (!s.started_at || !s.finished_at) return null;
  const ms = new Date(s.finished_at).getTime() - new Date(s.started_at).getTime();
  if (!isFinite(ms) || ms < 0) return null;
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`;
}

// ------------------------------------------------------------------ stepper
export function StageStepper({ stages }: { stages: PipelineStage[] }) {
  return (
    <div className="overflow-x-auto pb-1 pt-1.5 px-1" role="list" aria-label="Pipeline stages">
      <div className="flex items-start min-w-[640px]">
        {stages.map((s, i) => {
          const tone = STAGE_TONE[s.status];
          const last = i === stages.length - 1;
          return (
            <div key={s.key} className={`flex items-start ${last ? "" : "flex-1"}`} role="listitem">
              <div className="flex flex-col items-center w-[96px] shrink-0 text-center">
                <span
                  className={`pl-node ui-tone-${tone} ${s.status === "running" ? "is-running" : ""} ${s.status === "failed" ? "ring-2 ring-offset-2" : ""}`}
                  style={s.status === "failed" ? ({ ["--tw-ring-color" as any]: "var(--bad-fg)", ["--tw-ring-offset-color" as any]: "var(--surface)" }) : undefined}
                  aria-label={`${s.label}: ${STAGE_WORD[s.status]}`}
                >
                  {STAGE_GLYPH[s.status] || i + 1}
                </span>
                <span className="mt-1.5 text-[0.8125rem] leading-tight font-semibold ui-text" title={s.label}>{s.label.replace(/\s*\(.*\)$/, "")}</span>
                <span className="text-xs font-semibold" style={{ color: `var(--${tone}-fg)` }}>{STAGE_WORD[s.status]}</span>
              </div>
              {!last && (
                <div className={`pl-rail mt-[15px] ${s.status === "failed" ? "is-bad" : ["passed", "warning"].includes(s.status) ? "is-done" : ""}`} />
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ------------------------------------------------------------ failure banner
const NEXT_STEP: Record<string, string> = {
  connection: "The platform could not reach the device. Check the management address, routing/firewall and that the transport's port is open, then retry.",
  authentication: "The device rejected the credentials. Rotate or correct the credential reference for this device and retry.",
  unsupported: "This transport is unavailable for this device or vendor. Pick a different transport (SSH / NETCONF / gNMI) and retry.",
  commit_rejected: "The device refused one of the pushed commands. Review the commands and the device's own message, edit the proposal (this resets approval), then re-approve.",
  commit_failed: "The push failed part-way. Collect a fresh config from the device before retrying.",
  stale_hash: "The device's config changed after this change was validated, so nothing was pushed. Re-run validation against the current config and re-approve.",
  no_plan: "No safe, minimal command set could be derived. Edit the proposed commands and re-approve.",
  verification_mismatch: "The commit went through but the device's config differs from what was approved. Compare the diff, and roll back if it is unexpected.",
  verification_unavailable: "The commit was accepted but the device could not be re-read, so its real state is unverified. Investigate before doing anything else.",
  credentials: "Device credentials could not be resolved. Check the credential reference and vault access.",
  target_controls_failed: "The change was applied, but the controls it was meant to fix did not flip to PASS. Review the failing controls below, then fix forward or roll back.",
  internal: "The platform hit an unexpected error while running this stage. Check the server logs; the device state may be unverified.",
  no_archive: "There is no archived pre-change config to roll back to. Recover from a known-good backup or console access.",
  archive_read: "The archived pre-change config could not be read from object storage. Recover manually.",
  no_safe_delta: "No safe minimal revert could be derived. Manual recovery is required.",
  unverified: "The revert was pushed but the device could not be re-read. Its state is unverified — treat as critical.",
  hash_mismatch: "The device is not back on the pre-change config after the revert. Treat as critical and recover manually.",
};

/** What the auditor most needs to know: did anything reach the device? */
function deviceImpact(failedKey: string, isRollback: boolean): { tone: Tone; text: string } {
  if (isRollback) {
    if (["archive", "credentials", "plan"].includes(failedKey)) return { tone: "ok", text: "No revert commands were sent — the device is still on the post-change config." };
    if (failedKey === "push") return { tone: "warn", text: "The revert push failed part-way; the device may be in a mixed state." };
    return { tone: "warn", text: "The revert was pushed but could not be confirmed." };
  }
  if (["credentials", "connect", "precheck", "plan"].includes(failedKey)) return { tone: "ok", text: "No commands were pushed — the device configuration was not touched." };
  if (failedKey === "commit") return { tone: "warn", text: "The push failed part-way; some commands may have been applied. Re-collect the device config before retrying." };
  return { tone: "warn", text: "The change WAS pushed to the device." };
}

export function FailureBanner({ stages, failureLabel, isRollback = false }: {
  stages: PipelineStage[]; failureLabel?: string | null; isRollback?: boolean;
}) {
  const f = stages.find((s) => s.status === "failed");
  if (!f) return null;
  const impact = deviceImpact(f.key, isRollback);
  return (
    <div className="ui-callout ui-tone-bad space-y-2" role="alert">
      <div className="flex items-center gap-2 flex-wrap">
        <span className="font-bold">Stopped at: {f.label}</span>
        {(failureLabel || f.kind) && <Chip tone="bad">{failureLabel || f.kind}</Chip>}
      </div>
      {f.error && <div className="ui-callout-body text-sm ui-mono break-words">{f.error}</div>}
      {f.kind && NEXT_STEP[f.kind] && <div className="ui-callout-body text-sm">{NEXT_STEP[f.kind]}</div>}
      <div className={`ui-callout ui-tone-${impact.tone} text-sm font-medium`}>{impact.text}</div>
    </div>
  );
}

// -------------------------------------------------------------- stage detail
export function StageDetails({ stages }: { stages: PipelineStage[] }) {
  return (
    <ol className="ui-inset divide-y" style={{ borderColor: "var(--border)" }}>
      {stages.map((s) => {
        const tone = STAGE_TONE[s.status];
        return (
          <li key={s.key} className="flex gap-3 px-3 py-2 text-sm items-start" style={{ borderColor: "var(--border)" }}>
            <span className="w-[92px] shrink-0"><Chip tone={tone}>{STAGE_WORD[s.status]}</Chip></span>
            <div className="min-w-0 flex-1">
              <div className="font-semibold ui-text">{s.label}</div>
              {s.detail && <div className="ui-muted break-words">{s.detail}</div>}
              {s.error && s.status === "failed" && <div className="break-words" style={{ color: "var(--bad-fg)" }}>{s.error}</div>}
            </div>
            <span className="text-xs ui-muted shrink-0 tabular-nums">{durationOf(s) || ""}</span>
          </li>
        );
      })}
    </ol>
  );
}

// ------------------------------------------------------- post-validation view
function Verdict({ label, value, toneOf }: { label: string; value?: string | null; toneOf?: string | null }) {
  return (
    <div className="ui-inset px-3 py-2 min-w-[120px]">
      <div className="ui-label">{label}</div>
      <div className="mt-1"><Chip tone={verdictTone(toneOf ?? value)}>{(value || "—").replace(/_/g, " ")}</Chip></div>
    </div>
  );
}

export function PostValidationPanel({ pv, title = "Post-validation" }: { pv: PostValidation | null | undefined; title?: string }) {
  if (!pv) {
    return <div className="ui-inset px-3 py-2 text-sm ui-muted">{title} did not run — an earlier stage stopped the pipeline.</div>;
  }
  const diff = pv.batfish_diff && Object.keys(pv.batfish_diff).length ? pv.batfish_diff : null;
  return (
    <div className="space-y-3">
      <div className="flex gap-2 flex-wrap">
        <Verdict label="OPA policy" value={pv.opa_decision} />
        <Verdict label="Batfish (device)" value={pv.batfish_status} />
        <Verdict label="Risk" toneOf={pv.risk_level} value={pv.risk_level ? `${pv.risk_level}${pv.risk_score != null ? ` (${pv.risk_score})` : ""}` : null} />
        <Verdict label="Final decision" value={pv.final_decision} />
      </div>
      {pv.final_reason && <div className="text-sm ui-muted">{pv.final_reason}</div>}

      {pv.target_control_ids && pv.target_control_ids.length > 0 && (
        <div>
          <div className="ui-label mb-1">Targeted controls</div>
          <div className="flex gap-2 flex-wrap">
            {(pv.target_controls_result || pv.target_control_ids.map((c) => ({ control_id: c, result: "NOT_EVALUATED" }))).map((c) => (
              <Chip key={c.control_id} tone={c.result === "PASS" ? "ok" : c.result === "FAIL" ? "bad" : "warn"}>
                {c.control_id}: {c.result.replace(/_/g, " ")}
              </Chip>
            ))}
          </div>
        </div>
      )}

      {pv.findings_failed ? (
        <div>
          <div className="ui-label mb-1">Failing controls on the device now ({pv.findings_failed} of {pv.findings_total})</div>
          <ul className="ui-inset divide-y text-sm" style={{ borderColor: "var(--border)" }}>
            {(pv.failed_controls || []).slice(0, 6).map((f, i) => (
              <li key={i} className="px-3 py-1.5 flex gap-2 items-center" style={{ borderColor: "var(--border)" }}>
                <Chip tone={verdictTone(f.severity)}>{f.severity || "—"}</Chip>
                <span className="ui-mono ui-text">{f.control_id}</span>
                <span className="ui-muted truncate">{f.title}</span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      <div>
        <div className="ui-label mb-1">Batfish before → after (this change)</div>
        <div className="flex items-center gap-2 flex-wrap text-sm">
          <Chip tone={verdictTone(pv.batfish_diff_status)}>{(pv.batfish_diff_status || "NOT RUN").replace(/_/g, " ")}</Chip>
          <span className="ui-text">{pv.batfish_diff_summary || "No before/after comparison was recorded."}</span>
        </div>
        {diff && <div className="mt-2"><BatfishDeltaView diff={diff} /></div>}
      </div>

      {pv.scan_id && (
        <div className="flex gap-4 flex-wrap text-sm">
          <Link className="ui-link" to={`/scans/${pv.scan_id}`}>Open the full post-validation scan →</Link>
          <Link className="ui-link" to={`/evidence?scan_id=${pv.scan_id}`}>View anchored evidence →</Link>
        </div>
      )}
    </div>
  );
}

// ------------------------------------------------------------------- rollback
function RollbackAttempt({ rb }: { rb: RollbackRecord }) {
  const [open, setOpen] = useState(rb.status !== "VERIFIED");
  return (
    <div className="ui-inset p-3 space-y-3">
      <div className="flex items-center gap-2 flex-wrap">
        <span className="font-semibold ui-text">Rollback</span>
        <Chip tone={verdictTone(rb.status)}>{rb.status.replace(/_/g, " ")}</Chip>
        <span className="text-sm ui-muted">
          by {rb.initiated_by || "—"}{rb.started_at ? ` · ${fmt(rb.started_at)}` : ""}
        </span>
        <button className="ui-btn ui-btn-ghost ui-btn-sm ml-auto" onClick={() => setOpen((o) => !o)}>
          {open ? "Hide detail" : "Show detail"}
        </button>
      </div>
      {rb.reason && <div className="text-sm ui-text"><span className="ui-label mr-2">Reason</span>{rb.reason}</div>}
      <StageStepper stages={rb.stages} />
      <FailureBanner stages={rb.stages} failureLabel={rb.failure_label} isRollback />
      {open && (
        <>
          <StageDetails stages={rb.stages} />
          <div className="text-sm ui-muted">
            target (pre-change) hash <span className="ui-mono ui-text">{short(rb.target_config_hash)}</span>
            {" · "}post-rollback hash <span className="ui-mono ui-text">{short(rb.post_rollback_hash)}</span>
            {" · "}
            {rb.post_rollback_verified === null ? "unverified" : rb.post_rollback_verified ? "hashes match" : "hashes DO NOT match"}
          </div>
          {rb.post_validation && <PostValidationPanel pv={rb.post_validation} title="Post-rollback validation" />}
        </>
      )}
    </div>
  );
}

function RollbackAction({ d, crId, canRollback, onChanged }: {
  d: DeploymentRecord; crId: string; canRollback: boolean; onChanged: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState(d.rollback_recommended && (d.error || "").startsWith("[SIMULATED DRIFT]") ? "Reverting a simulated drift (developer sandbox)." : "");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const eligible = (d.status === "DRIFTED" || d.status === "VERIFIED") && !d.rolled_back;
  if (!eligible) return null;
  const recommended = d.status === "DRIFTED";

  async function go() {
    setBusy(true);
    setMsg(null);
    try {
      await endpoints.rollbackDeployment(crId, d.id, reason.trim());
      setOpen(false);
      onChanged();
    } catch (e: any) {
      setMsg(e?.response?.status === 403
        ? "Your role can't roll back deployments — admin or operator is required."
        : errText(e, "Rollback failed — see server logs."));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className={`ui-callout ${recommended ? "ui-tone-bad" : "ui-tone-idle"} space-y-2`}>
      <div className="font-bold">
        {recommended ? "Hash mismatch — rollback recommended" : "Rollback available"}
      </div>
      <div className="ui-callout-body text-sm">
        {recommended ? (
          <>
            The device's post-change config hash doesn't match what verification expected, so a
            rollback-required alert was raised. Rolling back pushes a revert derived from the{" "}
            <strong>pre-deployment config hash</strong> (<span className="ui-mono">{short(d.observed_pre_hash)}</span>) —
            the snapshot collected from this device immediately before the change was pushed — and re-hashes
            the device afterward to confirm it actually landed back on that state. Nothing reverts automatically;
            an operator must decide.
          </>
        ) : (
          <>
            This deployment verified successfully. You can still revert it to the pre-deployment config
            (hash <span className="ui-mono">{short(d.observed_pre_hash)}</span>, collected before this change was
            pushed); the revert is verified by re-collecting and hashing the device afterward.
          </>
        )}
      </div>
      {!canRollback ? (
        <div className="text-sm italic ui-muted">Requires the admin or operator role.</div>
      ) : !open ? (
        <button className="ui-btn ui-btn-danger" onClick={() => setOpen(true)}>Roll back to pre-change config…</button>
      ) : (
        <div className="space-y-2">
          <label className="ui-label block" htmlFor={`rb-${d.id}`}>Reason (required, recorded in the audit trail)</label>
          <textarea id={`rb-${d.id}`} className="ui-field" rows={2} value={reason}
            onChange={(e) => setReason(e.target.value)} placeholder="Why is this being reverted?" />
          <div className="flex gap-2">
            <button className="ui-btn ui-btn-danger" disabled={busy || reason.trim().length < 3} onClick={go}>
              {busy ? "Reverting…" : "Confirm rollback"}
            </button>
            <button className="ui-btn ui-btn-neutral" disabled={busy} onClick={() => setOpen(false)}>Cancel</button>
          </div>
        </div>
      )}
      {msg && <div className="text-sm font-medium" style={{ color: "var(--bad-fg)" }}>{msg}</div>}
    </div>
  );
}

// ---------------------------------------------------------------- main card
export function DeploymentPipelineCard({ d, crId, canRollback, onChanged }: {
  d: DeploymentRecord; crId: string; canRollback: boolean; onChanged: () => void;
}) {
  const simulated = (d.error || "").startsWith("[SIMULATED DRIFT]");
  const running = d.status === "PENDING" || d.status === "DEPLOYING" || d.stages.some((s) => s.status === "running");
  const [showStages, setShowStages] = useState(false);
  return (
    <div className="ui-inset p-4 space-y-3">
      <div className="flex items-center gap-2 flex-wrap">
        <span className="font-semibold ui-text">Deployment</span>
        <Chip tone={verdictTone(d.status)}>{d.status.replace(/_/g, " ")}</Chip>
        {running && <Chip tone="info">In progress…</Chip>}
        {simulated && <Chip tone="warn" title="Injected by the developer drift simulator — no real drift occurred.">SIMULATED</Chip>}
        {d.rolled_back && <Chip tone="ok">ROLLED BACK</Chip>}
        <span className="text-sm ui-muted">
          {d.transport || "—"} · by {d.initiated_by || "—"}{d.started_at ? ` · ${fmt(d.started_at)}` : ""}
        </span>
      </div>

      {d.stages_derived && (
        <div className="text-xs ui-muted">
          This deployment predates per-stage tracking, so the stages below are reconstructed from its status and error text.
        </div>
      )}

      <StageStepper stages={d.stages} />
      <FailureBanner stages={d.stages} failureLabel={d.failure_label} />

      <button className="ui-btn ui-btn-ghost ui-btn-sm" onClick={() => setShowStages((v) => !v)}>
        {showStages ? "Hide stage detail" : "Show stage detail"}
      </button>
      {showStages && <StageDetails stages={d.stages} />}

      <div className="text-sm ui-muted">
        pre-change hash <span className="ui-mono ui-text">{short(d.observed_pre_hash)}</span>
        {d.expected_pre_hash && d.observed_pre_hash && d.expected_pre_hash !== d.observed_pre_hash && (
          <> (validated against <span className="ui-mono ui-text">{short(d.expected_pre_hash)}</span>)</>
        )}
        {" · "}post-change hash <span className="ui-mono ui-text">{short(d.post_config_hash)}</span>
        {" · "}config verification{" "}
        <strong className="ui-text">{d.post_verification_passed === null ? "—" : d.post_verification_passed ? "passed" : "FAILED"}</strong>
      </div>

      {d.transport === "gnmi" && (d.model_name || d.request_hash) && (
        <div className="text-sm ui-muted">
          model <span className="ui-mono ui-text">{d.model_name || "—"}</span> · operation{" "}
          <span className="ui-mono ui-text">{d.operation || "—"}</span>
          {d.paths && d.paths.length > 0 && <> · paths <span className="ui-mono ui-text">{d.paths.join(", ")}</span></>}
          {" · "}request hash <span className="ui-mono ui-text">{d.request_hash || "—"}</span>
        </div>
      )}

      {d.verification_engine && (
        <div className="text-sm ui-muted">
          Supplemental verification ({d.verification_engine}):{" "}
          <strong style={{ color: d.verification_result === "PYATS_OK" ? "var(--ok-fg)" : "var(--warn-fg)" }}>{d.verification_result || "—"}</strong>
          {" "}— never authoritative; OPA / Batfish / risk decide compliance.
        </div>
      )}

      <div>
        <div className="ui-label mb-2">Post-validation</div>
        <PostValidationPanel pv={d.post_validation} />
      </div>

      <RollbackAction d={d} crId={crId} canRollback={canRollback} onChanged={onChanged} />

      {(d.rollbacks || []).length > 0 && (
        <div className="space-y-2">
          <div className="ui-label">Rollback history</div>
          {(d.rollbacks || []).map((rb) => <RollbackAttempt key={rb.id} rb={rb} />)}
        </div>
      )}
    </div>
  );
}