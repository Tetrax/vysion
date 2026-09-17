import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],

  server: {
    host: "0.0.0.0",
    port: 5173,

    proxy: {
      "/api": {
        // Defaults to a backend running on the host, which is the normal local
        // setup. docker-compose.dev.yml overrides it with the service name,
        // since inside a container 127.0.0.1 is the container itself.
        target: process.env.VITE_PROXY_TARGET || "http://127.0.0.1:8000",
        changeOrigin: true,
      },
    },
  },
});