import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";
import { closeSync, openSync } from "node:fs";
import { join } from "node:path";

// The build output is embedded in the Go binary (see embed.go). The dist
// directory must exist with at least one file for `go build` to succeed on a
// fresh clone, so a .gitkeep is committed and restored after every build.
function keepDist(): Plugin {
  return {
    name: "keep-dist",
    closeBundle() {
      closeSync(openSync(join(__dirname, "dist", ".gitkeep"), "a"));
    },
  };
}

export default defineConfig({
  plugins: [react(), keepDist()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
  server: {
    proxy: {
      "/api": "http://127.0.0.1:8460",
    },
  },
});
