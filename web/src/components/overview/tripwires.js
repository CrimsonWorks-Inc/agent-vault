// The tripwire settings as the containment card reads them, in plain JS so
// the two rules below can be tested apart from the card (integrate-3 r6 B1).
//
// The daemon always sends the rules in force: the defaults until some are
// saved, with `rules_saved: false`. So the defaults must never be labelled,
// or turned on, as the owner's own rules.

/** The owner's saved rules (none until saved), and the rules to show: those, else the defaults. */
export function shownRules(tw) {
  const rules = tw?.rules_saved !== false && Array.isArray(tw?.rules) && tw.rules.length ? tw.rules : []
  return { rules, shown: rules.length ? rules : (Array.isArray(tw?.defaults) ? tw.defaults : []) }
}

/**
 * The signed body of the on/off switch. Turning on with no saved rules also
 * stores the defaults (`rules: 'defaults'`), which the daemon gates; with
 * saved rules it only enables them, so an edited rule is kept.
 */
export function toggleBody(tw) {
  if (tw?.enabled === true) return { enabled: false }
  const stored = tw?.rules_saved !== false && (tw?.rules || []).length > 0
  return stored ? { enabled: true } : { enabled: true, rules: 'defaults' }
}

/** The rules as typed in the editor, or an error said before any signature is spent. */
export function readRules(text) {
  let rules
  try { rules = JSON.parse(text) } catch (e) { throw new Error(`The rules are not JSON: ${e.message}`) }
  if (!Array.isArray(rules)) throw new Error('The rules must be a JSON list')
  return rules
}
