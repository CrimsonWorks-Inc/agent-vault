/** Join class names, skipping falsy ones. */
export function cx(...parts) {
  return parts.flat(Infinity).filter(Boolean).join(' ')
}
