/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        soc: {
          bg: "#0b1220",
          panel: "#111a2e",
          border: "#1e2a44",
          accent: "#22d3ee",
        },
      },
    },
  },
  plugins: [],
};
