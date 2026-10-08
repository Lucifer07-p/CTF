/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./app/**/*.{ts,tsx}", "./lib/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: "#0b0f14",
        panel: "#121821",
        accent: "#36d399",
        warn: "#f59e0b",
      },
    },
  },
  plugins: [],
};
