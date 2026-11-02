import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './styles/theme.css'
import { applyTheme, readTheme } from './lib/theme.js'
import { App } from './App.jsx'

// The remembered theme goes on before the first render. Nothing inline in
// index.html does it, so the CSP needs no 'unsafe-inline' (U2).
try { applyTheme(document.documentElement, readTheme(localStorage)) } catch { /* the system's choice stands */ }

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
