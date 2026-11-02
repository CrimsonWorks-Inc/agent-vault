// Light, dark, or whatever the system says (contract U6). The CSS follows
// prefers-color-scheme on its own; data-theme is set only when the human
// picked, and the pick is remembered in localStorage inside a try/catch.

export const THEME_KEY = 'agent-vault.theme'
export const THEMES = ['system', 'light', 'dark']

export function readTheme(storage) {
  try {
    const v = storage?.getItem(THEME_KEY)
    return THEMES.includes(v) ? v : 'system'
  } catch { return 'system' }
}

export function saveTheme(storage, theme) {
  try {
    if (theme === 'system') storage?.removeItem(THEME_KEY)
    else storage?.setItem(THEME_KEY, theme)
  } catch { /* the choice lasts as long as the tab */ }
}

/** Put the choice on <html>; 'system' removes it so the media query decides. */
export function applyTheme(root, theme) {
  if (!root) return
  if (theme === 'light' || theme === 'dark') root.setAttribute('data-theme', theme)
  else root.removeAttribute('data-theme')
}

/** What is showing now, for the toggle's icon and label. */
export function effectiveTheme(theme, prefersDark) {
  return theme === 'system' ? (prefersDark ? 'dark' : 'light') : theme
}

/** The toggle cycles system -> light -> dark -> system. */
export function nextTheme(theme) {
  return THEMES[(THEMES.indexOf(theme) + 1) % THEMES.length]
}
