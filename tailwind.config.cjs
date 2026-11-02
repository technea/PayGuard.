/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./public/**/*.{html,js}", "./scripts/**/*.mjs"],
  corePlugins: { preflight: false },
  theme: {
    extend: {
      colors: {
        guard: {
          void: "#030611",
          panel: "#0a1024",
          cyan: "#00f0ff",
          emerald: "#10b981",
          rose: "#f43f5e"
        }
      }
    }
  },
  plugins: []
};
