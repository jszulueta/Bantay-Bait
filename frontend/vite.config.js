import { defineConfig } from "vite"
import react from "@vitejs/plugin-react"
import { VitePWA } from "vite-plugin-pwa"

export default defineConfig({
  plugins: \\\[
    react(),
    VitePWA({
      registerType: "autoUpdate",
      injectRegister: "script",   // loads an external file, so it works with our strict CSP
      manifest: {
        name: "Bantay-Bait",
        short\\\_name: "Bantay-Bait",
        description: "Check a suspicious SMS before you act on it.",
        start\\\_url: "/",
        scope: "/",
        display: "standalone",
        background\\\_color: "#06231a",
        theme\\\_color: "#06231a",
        icons: \\\[
          { src: "/icons/pwa-192x192.png", sizes: "192x192", type: "image/png" },
          { src: "/icons/pwa-512x512.png", sizes: "512x512", type: "image/png" },
          { src: "/icons/pwa-512x512.png", sizes: "512x512", type: "image/png", purpose: "maskable" },
        ],
      },
      workbox: {
        globPatterns: \\\["\\\*\\\*/\\\*.{js,css,html,png,svg,woff2}"],
        navigateFallback: "/index.html",
        cleanupOutdatedCaches: true,
        // No runtimeCaching on purpose: the API is never cached (PR-04).
      },
    }),
  ],
})
