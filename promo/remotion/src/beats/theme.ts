// Brand tokens for the promo. Single source of truth; all beats import from here.
export const theme = {
  bg:         "#0a0a0a",
  bgPanel:    "#141414",
  text:       "#f5f5f5",
  textDim:    "#9a9a9a",
  rafterGreen:"#2ea44f",   // scanned-by-Rafter badge color
  danger:     "#ff3b30",
  warn:       "#ffaa00",
  accentTeal: "#00d4ff",
  mono: '"JetBrains Mono", "Berkeley Mono", ui-monospace, monospace',
  sans: '"Inter", system-ui, -apple-system, sans-serif',
};

export const easeOutExpo = (t: number) => (t === 1 ? 1 : 1 - Math.pow(2, -10 * t));
