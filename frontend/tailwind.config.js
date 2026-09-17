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
          text: "#f3f4f8",
          // Was #6b7590 -> only 3.81:1 against the rail bg (#141928), below
          // WCAG AA's 4.5:1 for normal text. Was then bumped to #8b93ab
          // (5.72:1), but that's still a dim, easy-to-miss gray next to
          // active white items. #c3c8d8 pushes it to ~9.4:1 so inactive
          // nav items are clearly readable, not just "passes contrast math".
          textDim: "#c3c8d8",
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
