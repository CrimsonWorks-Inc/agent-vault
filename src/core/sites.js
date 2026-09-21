// The closed vocabulary of injection sites. A credential field declares where
// its value may be substituted, and nowhere else is ever substituted. The
// request path is deliberately not a site.

export const SITE_KINDS = ['header', 'basic', 'query', 'json', 'form', 'url', 'proxy']

/**
 * Parse a site string into a descriptor.
 *   header:authorization:Bearer   header:x-api-key
 *   basic:user | basic:pass
 *   query:key
 *   json:/pointer/path | form:field
 *   url:userinfo    (L4 connectors only)
 */
export function parseSite(spec) {
  const kind = spec.slice(0, spec.indexOf(':') === -1 ? spec.length : spec.indexOf(':'))
  if (!SITE_KINDS.includes(kind)) throw new Error(`unknown site kind: ${spec}`)
  const rest = spec.slice(kind.length + 1)
  switch (kind) {
    case 'header': {
      // The scheme is optional and matched case-insensitively with tolerant
      // whitespace, per RFC 9110: "Bearer  x" and "bearer x" are the same site.
      const i = rest.indexOf(':')
      const name = (i === -1 ? rest : rest.slice(0, i)).toLowerCase()
      const scheme = i === -1 ? null : rest.slice(i + 1)
      if (!name) throw new Error(`header site needs a name: ${spec}`)
      return { spec, kind, name, scheme }
    }
    case 'basic': {
      if (rest !== 'user' && rest !== 'pass') throw new Error(`basic site must be user or pass: ${spec}`)
      return { spec, kind, part: rest }
    }
    case 'query':
    case 'form':
      if (!rest) throw new Error(`${kind} site needs a key: ${spec}`)
      return { spec, kind, key: rest }
    case 'json':
      if (!rest.startsWith('/')) throw new Error(`json site needs an RFC 6901 pointer: ${spec}`)
      return { spec, kind, pointer: rest }
    case 'url':
    case 'proxy':
      if (rest !== 'userinfo') throw new Error(`${kind} site must be userinfo: ${spec}`)
      return { spec, kind, part: rest }
    default:
      throw new Error(`unknown site: ${spec}`)
  }
}

export function parseSites(specs) {
  return specs.map(parseSite)
}

/** True when any declared site writes into the request body. */
export function hasBodySite(sites) {
  return sites.some((s) => s.kind === 'json' || s.kind === 'form')
}

/** Human- and agent-readable usage for a site, shown in discovery and errors. */
export function describeSite(site, placeholder = '<placeholder>') {
  switch (site.kind) {
    case 'header':
      return site.scheme
        ? `${headerCase(site.name)}: ${site.scheme} ${placeholder}`
        : `${headerCase(site.name)}: ${placeholder}`
    case 'basic':
      return site.part === 'user'
        ? `Authorization: Basic base64(${placeholder}:x)`
        : `Authorization: Basic base64(x:${placeholder})`
    case 'query': return `?${site.key}=${placeholder}`
    case 'form': return `form field ${site.key}=${placeholder}`
    case 'json': return `JSON body at ${site.pointer}`
    case 'url': return `connection string username field`
    case 'proxy': return `proxy userinfo`
    default: return site.spec
  }
}

function headerCase(name) {
  return name.split('-').map((p) => p.charAt(0).toUpperCase() + p.slice(1)).join('-')
}
