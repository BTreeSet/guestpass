import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The bundle is embedded in the Rust binary by rust-embed and served from the
// pass path, which is not a fixed prefix, so every asset URL must be relative.
export default defineConfig({
  plugins: [react()],
  base: "./",
  build: { outDir: "dist", emptyOutDir: true },
});
