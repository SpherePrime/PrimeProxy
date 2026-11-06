import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { resolve } from "path";

// Та же сборка идёт и в Electron (dist/index.html), и в Android (Capacitor
// забирает dist целиком в WebView) — расхождений между платформами нет.
export default defineConfig({
  plugins: [react()],
  // Относительные пути активов: Electron грузит dist через file://,
  // где корневые "/assets/..." не резолвятся (белое окно).
  base: "./",
  server: { port: 5173 },
  build: {
    outDir: "dist",
    rollupOptions: {
      input: {
        main: resolve(__dirname, "index.html"),
        installer: resolve(__dirname, "installer.html"),
      },
    },
  },
});
