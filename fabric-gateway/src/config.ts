// Environment-driven configuration for the fabric-gateway bridge.
// Crypto material paths point at what fabric/scripts/up.sh exports to
// fabric/network/crypto/org1 (mirroring test-network's own layout) and
// mounted read-only into this container by docker-compose.
import * as path from "path";

function env(name: string, fallback?: string): string {
  const v = process.env[name];
  if (v !== undefined && v !== "") return v;
  if (fallback !== undefined) return fallback;
  throw new Error(`Missing required environment variable: ${name}`);
}

export const config = {
  port: parseInt(env("PORT", "8080"), 10),

  channelName: env("FABRIC_CHANNEL", "compliance-audit-channel"),
  chaincodeName: env("FABRIC_CHAINCODE", "compliance-evidence"),
  mspId: env("FABRIC_MSP_ID", "Org1MSP"),

  // gRPC endpoint of the peer this gateway connects through.
  peerEndpoint: env("FABRIC_PEER_ENDPOINT", "peer0.org1.example.com:7051"),
  peerHostAlias: env("FABRIC_PEER_HOST_ALIAS", "peer0.org1.example.com"),

  // Crypto material (mounted read-only from fabric/network/crypto/org1).
  cryptoPath: env("FABRIC_CRYPTO_PATH", "/crypto/org1"),
  get tlsCertPath(): string {
    return env(
      "FABRIC_TLS_CERT_PATH",
      path.join(this.cryptoPath, "peers/peer0.org1.example.com/tls/ca.crt")
    );
  },
  get certDirPath(): string {
    return env(
      "FABRIC_CERT_DIR_PATH",
      path.join(this.cryptoPath, "users/User1@org1.example.com/msp/signcerts")
    );
  },
  get keyDirPath(): string {
    return env(
      "FABRIC_KEY_DIR_PATH",
      path.join(this.cryptoPath, "users/User1@org1.example.com/msp/keystore")
    );
  },

  // How long a single evaluate/submit call may take before the caller
  // (backend/app/services/fabric_service.py) should treat it as
  // FABRIC_UNAVAILABLE rather than hang the scan pipeline.
  evaluateTimeoutMs: parseInt(env("FABRIC_EVALUATE_TIMEOUT_MS", "5000"), 10),
  submitTimeoutMs: parseInt(env("FABRIC_SUBMIT_TIMEOUT_MS", "15000"), 10),
};
