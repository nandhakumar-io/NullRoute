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
        // Fixed navy control rail for the primary navigation — constant
        // across the light/dark content toggle, the way an instrument
        // panel doesn't change with the room lighting.
        rail: {
          DEFAULT: "#141928",
          alt: "#1b2137",
          border: "#262d45",
          text: "#aeb4c7",
          textDim: "#6b7590",
        },
        brand: {
          DEFAULT: "#28406f",
          strong: "#17264a",
          soft: "#eef1f8",
        },
        seal: {
          DEFAULT: "#8a5a19",
          soft: "#faf1e0",
        },
      },
    },
  },
  plugins: [],
};
