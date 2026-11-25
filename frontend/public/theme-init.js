// Applies the saved theme before first paint (kept external for a strict CSP).
try {
  var t = localStorage.getItem('reconlens-theme')
  if (t === 'light' || t === 'dark') document.documentElement.dataset.theme = t
} catch {
  /* storage unavailable: follow the system theme */
}
