import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Use VITE_BACKEND_URL .env var on the remote server to point at the actual
// FastAPI process — e.g. VITE_BACKEND_URL=http://172.17.1.6:8000
// Falls back to localhost:8000 for local dev.
const BACKEND = (process.env as Record<string, string>)["VITE_BACKEND_URL"] ?? "http://localhost:8000";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    host: "0.0.0.0",
    proxy: {
      // Route all /api/* and /health requests through the Vite dev server
      // to the backend — this avoids CORS completely regardless of which
      // IP/hostname the browser is using to access the frontend.
      "/api": { target: BACKEND, changeOrigin: true, secure: false },
      "/health": { target: BACKEND, changeOrigin: true, secure: false },
    },
  },
});
