// Builds a connected @hyperledger/fabric-gateway `Gateway` handle: mTLS
// gRPC connection to the peer, signer built from the client's MSP identity.
// This is the only file that touches raw crypto material — server.ts and
// evidenceContract.ts only ever see the resulting `Contract`.
import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import * as grpc from "@grpc/grpc-js";
import {
  connect,
  Contract,
  Gateway,
  Identity,
  Signer,
  signers,
} from "@hyperledger/fabric-gateway";
import { config } from "./config";

function firstFileIn(dir: string): string {
  const files = fs.readdirSync(dir);
  if (files.length === 0) {
    throw new Error(`No files found in ${dir}`);
  }
  return path.join(dir, files[0]);
}

function newGrpcConnection(): grpc.Client {
  const tlsRootCert = fs.readFileSync(config.tlsCertPath);
  const credentials = grpc.credentials.createSsl(tlsRootCert);
  return new grpc.Client(config.peerEndpoint, credentials, {
    "grpc.ssl_target_name_override": config.peerHostAlias,
  });
}

function newIdentity(): Identity {
  const certPath = firstFileIn(config.certDirPath);
  const credentials = fs.readFileSync(certPath);
  return { mspId: config.mspId, credentials };
}

function newSigner(): Signer {
  const keyPath = firstFileIn(config.keyDirPath);
  const privateKeyPem = fs.readFileSync(keyPath);
  const privateKey = crypto.createPrivateKey(privateKeyPem);
  return signers.newPrivateKeySigner(privateKey);
}

let cachedGateway: Gateway | null = null;
let cachedGrpcClient: grpc.Client | null = null;

/** Lazily connects (once) and returns the compliance-evidence Contract. */
export function getContract(): Contract {
  if (!cachedGateway) {
    cachedGrpcClient = newGrpcConnection();
    cachedGateway = connect({
      client: cachedGrpcClient,
      identity: newIdentity(),
      signer: newSigner(),
      evaluateOptions: () => ({ deadline: Date.now() + config.evaluateTimeoutMs }),
      endorseOptions: () => ({ deadline: Date.now() + config.submitTimeoutMs }),
      submitOptions: () => ({ deadline: Date.now() + config.submitTimeoutMs }),
      commitStatusOptions: () => ({ deadline: Date.now() + config.submitTimeoutMs }),
    });
  }
  const network = cachedGateway.getNetwork(config.channelName);
  return network.getContract(config.chaincodeName);
}

export function isConnected(): boolean {
  return cachedGateway !== null;
}

export function closeConnection(): void {
  cachedGateway?.close();
  cachedGrpcClient?.close();
  cachedGateway = null;
  cachedGrpcClient = null;
}
