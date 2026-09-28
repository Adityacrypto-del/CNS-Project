// Where the secure exam server is running. Override with VITE_WEB_APP_URL / VITE_API_URL
// when the Python server uses other ports (e.g. SECURE_EXAM_WEB_PORT=8445).
export const WEB_APP_URL = (import.meta.env.VITE_WEB_APP_URL ?? "https://localhost:5173").replace(/\/$/, "")
export const API_URL = (import.meta.env.VITE_API_URL ?? "https://localhost:8444").replace(/\/$/, "")

const port = (url: string) => new URL(url).port || "443"
export const WEB_APP_PORT = port(WEB_APP_URL)
export const API_PORT = port(API_URL)
