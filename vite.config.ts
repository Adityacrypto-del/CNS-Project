import { defineConfig, loadEnv, type ProxyOptions } from "vite"
import react from "@vitejs/plugin-react"
import { existsSync, readFileSync } from "fs"
import https from "https"
import path from "path"

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "")
  const apiUrl = env.VITE_API_URL ?? "https://localhost:8444"

  // The API only allows CORS from the exam web app, so the landing page reaches /api/v1/health
  // through this proxy. The server certificate is verified against the project CA from init_system.
  const caFile = path.resolve(env.SECURE_EXAM_DATA ?? "data", "pki", "ca_cert.pem")
  const proxy: Record<string, ProxyOptions> = {
    "/api/v1/health": {
      target: apiUrl,
      changeOrigin: true,
      secure: true,
      agent: existsSync(caFile) ? new https.Agent({ ca: readFileSync(caFile) }) : undefined,
    },
  }

  return {
    plugins: [react()],
    resolve: {
      alias: {
        "@": path.resolve(__dirname, "./src"),
      },
    },
    server: { port: 3000, strictPort: true, open: false, proxy },
    preview: { port: 3000, strictPort: true, proxy },
  }
})
