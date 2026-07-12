import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Build output is copied into the FastAPI package's static/ dir at package time.
export default defineConfig({
  plugins: [react()],
  base: "/",
  build: { outDir: "dist", emptyOutDir: true },
});
