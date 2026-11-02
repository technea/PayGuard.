import { mkdirSync } from "node:fs";
import { spawnSync } from "node:child_process";

const outputDirectory = "public/assets/css";
mkdirSync(outputDirectory, { recursive: true });

const command = process.platform === "win32" ? "npx.cmd" : "npx";
const args = [
  "--yes",
  "tailwindcss@3.4.17",
  "-c",
  "tailwind.config.cjs",
  "-i",
  "src/styles/tailwind.css",
  "-o",
  "public/assets/css/tailwind.css",
  "--minify"
];

const result = spawnSync(command, args, {
  stdio: "inherit",
  shell: process.platform === "win32"
});

if (result.error) {
  console.error("Tailwind CSS build could not start:", result.error.message);
  process.exit(1);
}
if (result.status !== 0) {
  process.exit(result.status ?? 1);
}
