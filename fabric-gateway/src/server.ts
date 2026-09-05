// Internal-only HTTP bridge between the FastAPI backend and the Fabric
// Gateway (section 18). Never expose this port to the browser — it is
// reached only over the docker-compose internal network by
// backend/app/services/fabric_service.py. No Fabric certificates or
// private keys are ever returned in a response body.
import express, { Request, Response, NextFunction } from "express";
import {
  anchorEvidence,
  getEvidence,
  verifyEvidence,
  getEvidenceHistory,
  AnchorEvidenceInput,
} from "./evidenceContract";
import { closeConnection } from "./fabricClient";
import { config } from "./config";

const app = express();
app.use(express.json({ limit: "256kb" })); // evidence anchors are small; bound the body defensively

function asyncHandler(fn: (req: Request, res: Response) => Promise<void>) {
  return (req: Request, res: Response, next: NextFunction) => {
    fn(req, res).catch(next);
  };
}

app.get("/health", (_req, res) => {
  res.json({ status: "ok", channel: config.channelName, chaincode: config.chaincodeName });
});

// POST /evidence  { evidenceId, scanId, ..., evidenceHash, ... }
app.post(
  "/evidence",
  asyncHandler(async (req, res) => {
    const body = req.body as Partial<AnchorEvidenceInput>;
    if (!body.evidenceId || !body.evidenceHash) {
      res.status(400).json({ error: "evidenceId and evidenceHash are required" });
      return;
    }
    const input: AnchorEvidenceInput = {
      evidenceId: body.evidenceId,
      scanId: body.scanId ?? "",
      deviceId: body.deviceId ?? "",
      tenantId: body.tenantId ?? "",
      eventType: body.eventType ?? "",
      evidenceHash: body.evidenceHash,
      configHash: body.configHash ?? "",
      baselineHash: body.baselineHash ?? "",
      opaDecision: body.opaDecision ?? "",
      batfishDecision: body.batfishDecision ?? "",
      finalDecision: body.finalDecision ?? "",
      policyVersion: body.policyVersion ?? "",
      batfishSnapshot: body.batfishSnapshot ?? "",
      modelVersion: body.modelVersion ?? "",
      timestamp: body.timestamp ?? new Date().toISOString(),
      actor: body.actor ?? "system:fabric-gateway",
      schemaVersion: body.schemaVersion ?? "1.0",
    };
    const anchored = await anchorEvidence(input);
    res.status(201).json(anchored);
  })
);

app.get(
  "/evidence/:id",
  asyncHandler(async (req, res) => {
    const record = await getEvidence(req.params.id);
    res.json(record);
  })
);

app.post(
  "/evidence/:id/verify",
  asyncHandler(async (req, res) => {
    const expectedHash = (req.body as { evidenceHash?: string })?.evidenceHash;
    if (!expectedHash) {
      res.status(400).json({ error: "evidenceHash is required" });
      return;
    }
    const match = await verifyEvidence(req.params.id, expectedHash);
    res.json({
      evidenceId: req.params.id,
      match,
      status: match ? "INTEGRITY_VERIFIED" : "INTEGRITY_FAILURE",
    });
  })
);

app.get(
  "/evidence/:id/history",
  asyncHandler(async (req, res) => {
    const history = await getEvidenceHistory(req.params.id);
    res.json(history);
  })
);

// eslint-disable-next-line @typescript-eslint/no-unused-vars
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  // Never leak stack traces / crypto paths to the caller — just enough for
  // the backend to distinguish "not found" from "Fabric unavailable".
  const message = err.message || "Fabric gateway error";
  const notFound = /does not exist/i.test(message);
  res.status(notFound ? 404 : 502).json({ error: message });
});

const server = app.listen(config.port, () => {
  // eslint-disable-next-line no-console
  console.log(`fabric-gateway listening on :${config.port} (channel=${config.channelName} chaincode=${config.chaincodeName})`);
});

function shutdown() {
  server.close(() => {
    closeConnection();
    process.exit(0);
  });
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
