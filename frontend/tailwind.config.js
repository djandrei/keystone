/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: "var(--bg)",
        panel: "var(--panel)",
        "panel-2": "var(--panel-2)",
        border: "var(--border)",
        stone: { DEFAULT: "var(--stone)", light: "var(--stone-light)" },
        amber: { DEFAULT: "var(--amber)", bright: "var(--amber-bright)" },
        fg: { DEFAULT: "var(--text)", muted: "var(--text-muted)" },
        good: "var(--good)",
        warn: "var(--warn)",
        critical: "var(--critical)",
        info: "var(--info)",
      },
      fontFamily: {
        display: ["Sora", "ui-sans-serif", "system-ui", "sans-serif"],
        sans: ['"IBM Plex Sans"', "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ['"IBM Plex Mono"', "ui-monospace", "monospace"],
      },
      borderRadius: { xl: "0.9rem", "2xl": "1.1rem" },
      boxShadow: {
        panel: "0 1px 0 0 rgba(255,255,255,0.03) inset, 0 8px 24px -12px rgba(0,0,0,0.6)",
        glow: "0 0 0 1px var(--amber), 0 6px 20px -8px rgba(245,158,11,0.5)",
      },
      keyframes: {
        "fade-in": { from: { opacity: "0" }, to: { opacity: "1" } },
        "slide-in": {
          from: { transform: "translateX(100%)", opacity: "0" },
          to: { transform: "translateX(0)", opacity: "1" },
        },
      },
      animation: {
        "fade-in": "fade-in 150ms ease-out",
        "slide-in": "slide-in 200ms cubic-bezier(0.16,1,0.3,1)",
      },
    },
  },
  plugins: [],
};
