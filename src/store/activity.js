export function summarizeSession(rows, { session, grants }) {
  let complete = true;
  let from_seq = null;
  let to_seq = null;
  let first_at = null;
  let last_at = null;
  
  let foundSessionCreated = false;
  
  const requests = { allowed: 0, denied: 0, held: 0 };
  const approvals = { requested: 0, granted: 0, denied: 0, replayed: 0 };
  const pathsCount = new Map();
  const denialsCount = new Map();
  const tripwires = [];

  const grantIds = new Set(grants.map(g => g.id));
  
  for (const r of rows) {
    if (from_seq === null || r.seq < from_seq) from_seq = r.seq;
    if (to_seq === null || r.seq > to_seq) to_seq = r.seq;
    if (first_at === null || r.ts < first_at) first_at = r.ts;
    if (last_at === null || r.ts > last_at) last_at = r.ts;
    
    if (r.kind === 'audit.anchor_missing' || r.kind === 'audit.truncation_detected') {
      complete = false;
    }
    
    if (r.kind === 'session.created' && r.session_id === session.id) {
      foundSessionCreated = true;
    }
    
    if (r.session_id === session.id) {
      if (r.kind === 'request.allowed') {
        requests.allowed++;
        const key = `${r.method} ${r.path}`;
        const entry = pathsCount.get(key) || { method: r.method, path: r.path, count: 0, last_at: r.ts };
        entry.count++;
        entry.last_at = r.ts > entry.last_at ? r.ts : entry.last_at;
        pathsCount.set(key, entry);
      } else if (r.kind === 'request.denied') {
        requests.denied++;
        const key = `${r.method} ${r.path}`;
        const entry = pathsCount.get(key) || { method: r.method, path: r.path, count: 0, last_at: r.ts };
        entry.count++;
        entry.last_at = r.ts > entry.last_at ? r.ts : entry.last_at;
        pathsCount.set(key, entry);
        
        const dKey = `${r.code}|${r.rule}`;
        const dEntry = denialsCount.get(dKey) || { code: r.code, rule: r.rule, count: 0 };
        dEntry.count++;
        denialsCount.set(dKey, dEntry);
      } else if (r.kind === 'tripwire.fired') {
        tripwires.push({ rule_id: r.rule_id, at: r.ts });
      }
    }
    
    // Check approval.requested by matching grant_id
    if (grantIds.has(r.grant_id)) {
      if (r.kind === 'approval.requested') {
        approvals.requested++;
        requests.held++;
      } else if (r.kind === 'approval.granted') approvals.granted++;
      else if (r.kind === 'approval.denied') approvals.denied++;
      else if (r.kind === 'approval.replayed') approvals.replayed++;
    }
  }

  if (!foundSessionCreated) complete = false;
  
  const paths = Array.from(pathsCount.values()).sort((a, b) => b.count - a.count).slice(0, 50);
  const denials = Array.from(denialsCount.values());

  let note = null;
  if (!complete) note = 'History is incomplete; the log started after the session or an anchor is missing.';

  return {
    complete, note, from_seq, to_seq, first_at, last_at,
    requests, paths, denials, approvals, tripwires
  };
}

export function accessReport(rows, { sessions, grants, credentials, since }) {
  let complete = true;
  let from_seq = null;
  
  const credStats = new Map();
  for (const c of Object.values(credentials)) {
    credStats.set(c.id, {
      slug: c.slug, sessions_active: 0, sessions_total: 0, requests: 0, denials: 0, last_used_at: null,
      expires_at: c.expires_at || null, expiry_warning: c.expiry_warning || null,
      health_status: c.health?.status || null, quarantined: !!c.quarantine
    });
  }
  
  const sessStats = new Map();
  for (const s of Object.values(sessions)) {
    sessStats.set(s.id, {
      id: s.id, label: s.label, state: s.state, creds: [], requests: 0, denials: 0,
      last_seen_at: s.last_seen_at, elevated: !!s.elevated, unused_methods: [],
      // internal trackers
      methods_granted: new Set(),
      methods_used: new Set()
    });
  }
  
  for (const g of Object.values(grants)) {
    const s = sessStats.get(g.session_id);
    if (s && g.credential_id) {
       const cs = credStats.get(g.credential_id);
       if (cs && !s.creds.includes(cs.slug)) s.creds.push(cs.slug);
       if (g.policy?.methods) {
         for (const m of g.policy.methods) s.methods_granted.add(m);
       }
    }
    const cStat = credStats.get(g.credential_id);
    if (cStat) {
       cStat.sessions_total++;
       if (g.state === 'active') cStat.sessions_active++;
    }
  }

  for (const r of rows) {
    if (r.kind === 'audit.anchor_missing' || r.kind === 'audit.truncation_detected') {
      complete = false;
    }
    if (r.session_id) {
       const s = sessStats.get(r.session_id);
       if (s) {
         if (r.kind === 'request.allowed') {
           s.requests++;
           s.methods_used.add(r.method);
           
           // Credential request update
           if (r.credential_slug) {
             for (const c of credStats.values()) {
               if (c.slug === r.credential_slug) {
                 c.requests++;
                 c.last_used_at = r.ts > (c.last_used_at || '') ? r.ts : c.last_used_at;
               }
             }
           }
         } else if (r.kind === 'request.denied') {
           s.denials++;
           if (r.credential_slug) {
             for (const c of credStats.values()) {
               if (c.slug === r.credential_slug) {
                 c.denials++;
               }
             }
           }
         }
       }
    }
  }

  for (const s of sessStats.values()) {
    s.unused_methods = Array.from(s.methods_granted).filter(m => !s.methods_used.has(m));
    delete s.methods_granted;
    delete s.methods_used;
  }

  return {
    generated_at: new Date().toISOString(),
    since,
    complete,
    credentials: Array.from(credStats.values()),
    sessions: Array.from(sessStats.values())
  };
}
