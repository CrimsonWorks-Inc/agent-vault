# agent-vault brand

agent-vault is a product of **ioLite Labs**, and it should look like one: serious, restrained, and exact. The page guards credentials, so it reads as a security instrument and never as a template.

## Sources

Read from the live sites on 2026-11-01, not guessed:

- https://iolitelabs.com and https://iolitelabs.com/agent-vault, including the site's stylesheet (`/_next/static/chunks/*.css`) and its brand files (`/brand/logo-horizontal.svg`, `/brand/logo-horizontal-white-lilac.svg`, `/agent-vault-mark.svg`).
- Site tokens, dark by default: `--base: 7 7 19`, `--panel: 12 12 32`, `--panel2: 15 16 48`, `--ink: 255 255 255`, `--accent: 194 165 243` (lilac).
- Site tokens, light: `--base: 246 245 252`, `--panel2: 239 235 250`, `--ink: 13 18 85` (navy), `--accent: 56 53 152` (indigo).
- The ioLite logo: navy `#0D1255` with indigo `#383598`; on dark, white with lilac `#C2A5F3`.
- The agent-vault page's own colours: periwinkle `#8F9BFF`, the mark's gradient (`#7C8BFF` to `#5468FF` to `#3B2FB8`), green `#7BE3A6` / `#1F8A5B`, red `#FF8A7A` / `#C0392B`.
- Type: Inter for everything; system monospace for code; uppercase, widely tracked mono labels above sections; generous rounding (`rounded-xl` cards, pill badges).

## Palette

Defined once, in `src/styles/theme.css`, as CSS variables that Tailwind turns into utilities (`bg-surface`, `text-muted`, `border-line`). Tailwind's default colours are cleared, so nothing else exists. Every text pair below meets WCAG AA (4.5:1) in both themes. Status is never colour alone: a badge always says its state in words.

| Role | Light | Dark | Use |
|---|---|---|---|
| `bg` | `#F6F5FC` | `#070713` | page background (ioLite base) |
| `surface` | `#FFFFFF` | `#0C0C20` | cards, dialogs (ioLite panel) |
| `sunken` | `#EFEBFA` | `#0F1030` | code, skeletons, hover rows (ioLite panel2) |
| `ink` | `#0D1255` | `#E6E8F5` | text (ioLite navy in light) |
| `muted` | `#4E5378` | `#A3A8CC` | secondary text, 6.8:1 / 8.6:1 on bg |
| `line` | `#DDDAEF` | `#23244D` | dividers (decorative) |
| `line-strong` | `#8E8AB5` | `#5A5D9A` | input borders (3:1, WCAG 1.4.11) |
| `accent` | `#3B33B0` | `#8F9BFF` | links, primary buttons, the mark |
| `accent-soft` | `#ECEAFB` | `#1A1B52` | selected nav, info notices |
| `brand` | `#383598` | `#C2A5F3` | "by ioLite Labs" in the lockup |
| `ok` | `#17704A` | `#7BE3A6` | healthy, unlocked, on |
| `warn` | `#8A5300` | `#F2C46B` | waiting, expiring, agent-written text |
| `crit` | `#B42318` | `#FF8A7A` | locked, refused, panic |
| `focus` | `#5468FF` | `#C2A5F3` | the focus ring |

Light is the default. Dark follows `prefers-color-scheme`, and the sidebar's System / Light / Dark switch overrides it (`data-theme` on `<html>`, remembered in localStorage).

The accent is agent-vault's own: ioLite's indigo, nudged toward the mark's `#3B2FB8` in light, and the agent-vault page's periwinkle in dark. Lilac belongs to the parent brand, and appears only in "by ioLite Labs" and the dark focus ring.

## Type

- **Inter Variable** (OFL-1.1), the face iolitelabs.com uses, from `@fontsource-variable/inter`. Latin and Latin Extended subsets only, bundled by Vite and served from `/assets`.
- **JetBrains Mono Variable** (OFL-1.1) for ids, tokens, commands and agent-written text, from `@fontsource-variable/jetbrains-mono`.
- Nothing is fetched from a font CDN. Scripts outside those subsets fall back to the system font.
- Scale: 13 px body (`text-sm`), 14 px base, 20 to 24 px headings, `tracking-tight` on headings. Section labels ("eyebrows") are 11 px mono, uppercase, tracked `0.14em`, after the site's labels.

## Shape

- Radius: `rounded-control` 8 px for buttons and inputs, `rounded-card` 14 px for cards and dialogs, `rounded-pill` for badges.
- Shadow: `shadow-card` is a hairline lift. `shadow-raised` is for menus, dialogs and toasts only.
- Spacing: Tailwind's 4 px grid. Cards pad 20 px, and rows inside cards are divided by `line`.

## Mark and lockup

- **Mark** (`src/ui/mark.svg`, drawn as JSX in `components/ui/Mark.jsx`) is a vault door. It is the rounded hexagon of ioLite's agent-vault mark, with a dial ring, twelve ticks and agent-vault's original keyhole, all punched out of one shape in `currentColor`. Under 24 px it drops the ticks, which are the first detail to blur.
- **Lockup** (`<Logo />`): the mark in `accent`, then "agent-vault" in Inter semibold, with the hyphen in `accent`. Beneath it sits "BY IOLITE LABS" in mono uppercase, tracked, in `brand`. The parent is smaller and quieter: this is a product of the lab, not the lab's name.
- **Favicon** (`src/assets/favicon.svg`): the compact mark in the published gradient. A favicon cannot read a theme, so it is the one place literal colours are allowed.

## Voice

The site's voice, applied to an operator's console:

- **Short and declarative.** "The vault is locked." "Nothing comes back by itself."
- **Say what happens, then what to do.** "Every proxied request is refused until it is unlocked."
- **Never cute.** Don't use exclamation marks, emoji or "Oops". A refusal is the system working, so say it plainly.
- **Name the exact thing.** Write "Touch ID to revoke session s_123", not "Confirm action".
- **Agent-written text is quoted, never adopted.** It is shown in mono, in a dashed `warn` box, labelled "Written by the agent, not verified".
