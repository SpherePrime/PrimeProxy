import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Та же сборка идёт и в Electron (dist/index.html), и в Android (Capacitor
// забирает dist целиком в WebView) — расхождений между платформами нет.
export default defineConfig({
  plugins: [react()],
  server: { port: 5173 },
  build: { outDir: "dist" },
});
