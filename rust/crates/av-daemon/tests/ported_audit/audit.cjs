// Parse sources only: never import a test file or execute a hook/test body.
const fs = require("node:fs"),
  path = require("node:path"),
  cp = require("node:child_process");
process.chdir(
  cp
    .execFileSync("git", ["rev-parse", "--show-toplevel"], { encoding: "utf8" })
    .trim(),
);
const acorn = require("internal/deps/acorn/acorn/dist/acorn");
const U = Symbol("unknown");
const sources = ["legacy/js/test/security", "legacy/js/test/core"].flatMap((d) =>
  fs
    .readdirSync(d)
    .filter((f) => f.endsWith(".test.js"))
    .map((f) => `${d}/${f}`),
);
const cases = [],
  unresolved = [],
  stack = [];
function ev(n, e) {
  if (!n) return U;
  switch (n.type) {
    case "ArrowFunctionExpression":
    case "FunctionExpression":
      return { fn: n, env: new Map(e) };
    case "BlockStatement": {
      let sub = new Map(e);
      for (let x of n.body) {
        if (x.type === "VariableDeclaration")
          for (let d of x.declarations) bind(d.id, ev(d.init, sub), sub);
        else if (x.type === "ReturnStatement") return ev(x.argument, sub);
        else return U;
      }
      return U;
    }
    case "Literal":
      return n.value;
    case "Identifier":
      return e.has(n.name) ? e.get(n.name) : U;
    case "ArrayExpression":
      return n.elements.map((x) => ev(x, e));
    case "ObjectExpression": {
      let o = {};
      for (const p of n.properties) {
        if (p.type !== "Property") return U;
        const k = p.computed ? ev(p.key, e) : (p.key.name ?? p.key.value);
        if (k === U) return U;
        o[k] = ev(p.value, e);
      }
      return o;
    }
    case "TemplateLiteral": {
      let s = n.quasis[0].value.cooked;
      for (let i = 0; i < n.expressions.length; i++) {
        let v = ev(n.expressions[i], e);
        if (v === U) return U;
        s += v + n.quasis[i + 1].value.cooked;
      }
      return s;
    }
    case "UnaryExpression": {
      let v = ev(n.argument, e);
      if (v === U) return U;
      if (n.operator === "-") return -v;
      if (n.operator === "+") return +v;
      if (n.operator === "!") return !v;
      return U;
    }
    case "BinaryExpression": {
      let a = ev(n.left, e),
        b = ev(n.right, e);
      if (a === U || b === U) return U;
      switch (n.operator) {
        case "+":
          return a + b;
        case "-":
          return a - b;
        case "<":
          return a < b;
        case "<=":
          return a <= b;
        case ">":
          return a > b;
        case ">=":
          return a >= b;
      }
      return U;
    }
    case "MemberExpression": {
      let o = ev(n.object, e),
        k = n.computed ? ev(n.property, e) : n.property.name;
      return o === U || k === U ? U : (o?.[k] ?? U);
    }
    case "CallExpression": {
      let c = n.callee;
      if (c.type === "Identifier") {
        let f = ev(c, e);
        if (f !== U && f?.fn) {
          let sub = new Map(f.env);
          f.fn.params.forEach((p, i) => bind(p, ev(n.arguments[i], e), sub));
          return ev(f.fn.body, sub);
        }
        return U;
      }
      if (c.type !== "MemberExpression") return U;
      let k = c.computed ? ev(c.property, e) : c.property.name;
      let args = n.arguments.map((a) => ev(a, e));
      if (
        c.object.type === "Identifier" &&
        c.object.name === "JSON" &&
        k === "stringify" &&
        args[0] !== U
      )
        return JSON.stringify(args[0]);
      if (c.object.type === "Identifier" && c.object.name === "Object") {
        if (k === "freeze") return args[0];
        if (args[0] !== U) {
          if (k === "keys") return Object.keys(args[0]);
          if (k === "entries") return Object.entries(args[0]);
          if (k === "values") return Object.values(args[0]);
        }
      }
      let o = ev(c.object, e);
      if (k === "join" && Array.isArray(o) && !o.includes(U))
        return o.join(args[0] === U ? "," : args[0]);
      return U;
    }
    default:
      return U;
  }
}
function bind(p, v, e) {
  if (p.type === "Identifier") e.set(p.name, v);
  else if (p.type === "ArrayPattern")
    p.elements.forEach((x, i) => x && bind(x, v === U ? U : (v?.[i] ?? U), e));
  else if (p.type === "ObjectPattern")
    p.properties.forEach((x) => {
      if (x.type === "Property")
        bind(x.value, v === U ? U : (v?.[x.key.name ?? x.key.value] ?? U), e);
    });
}
function testCall(n) {
  if (n.type !== "CallExpression") return false;
  let c = n.callee;
  while (
    c.type === "MemberExpression" &&
    ["only", "skip", "todo"].includes(c.property.name)
  )
    c = c.object;
  return (
    (c.type === "Identifier" && ["test", "it", "nodeTest"].includes(c.name)) ||
    (c.type === "MemberExpression" &&
      c.property.name === "test" &&
      ["t", "ctx", "context"].includes(c.object.name))
  );
}
const cache = new WeakMap();
function contains(n) {
  if (!n || typeof n !== "object") return false;
  if (cache.has(n)) return cache.get(n);
  let yes =
    testCall(n) ||
    Object.entries(n).some(
      ([k, v]) =>
        k !== "loc" && (Array.isArray(v) ? v.some(contains) : contains(v)),
    );
  cache.set(n, yes);
  return yes;
}
function walk(n, e, file, inFunction = false) {
  if (!n || typeof n !== "object") return;
  if (Array.isArray(n)) {
    for (let x of n) walk(x, e, file, inFunction);
    return;
  }
  if (n.type === "VariableDeclaration") {
    for (let d of n.declarations) {
      bind(d.id, ev(d.init, e), e);
      if (contains(d.init)) walk(d.init, e, file, inFunction);
    }
    return;
  }
  if (n.type === "ForOfStatement") {
    if (!contains(n.body)) return;
    let a = ev(n.right, e);
    if (Array.isArray(a)) {
      for (let v of a) {
        let sub = new Map(e);
        bind(
          n.left.type === "VariableDeclaration"
            ? n.left.declarations[0].id
            : n.left,
          v,
          sub,
        );
        walk(n.body, sub, file, inFunction);
      }
    } else {
      unresolved.push({
        file,
        line: n.loc.start.line,
        reason: "dynamic loop around test declaration",
      });
      walk(n.body, new Map(e), file, inFunction);
    }
    return;
  }
  if (
    [
      "FunctionDeclaration",
      "FunctionExpression",
      "ArrowFunctionExpression",
    ].includes(n.type)
  ) {
    if (!contains(n.body)) return;
    let sub = new Map(e);
    n.params.forEach((p) => bind(p, U, sub));
    walk(n.body, sub, file, true);
    return;
  }
  if (testCall(n)) {
    let name = ev(n.arguments[0], e);
    if (typeof name === "string")
      cases.push({ file, name, line: n.loc.start.line, parent: [...stack] });
    else if (
      !(
        inFunction &&
        n.arguments[0]?.type === "Identifier" &&
        ["name", "title"].includes(n.arguments[0].name)
      )
    )
      unresolved.push({
        file,
        line: n.loc.start.line,
        reason: "unresolved test name",
        source: fs
          .readFileSync(file, "utf8")
          .slice(n.start, Math.min(n.end, n.start + 140)),
      });
    if (typeof name === "string") stack.push(name);
    for (let a of n.arguments.slice(1))
      if (contains(a)) walk(a, new Map(e), file, true);
    if (typeof name === "string") stack.pop();
    return;
  }
  for (let [k, v] of Object.entries(n))
    if (k !== "loc" && v && typeof v === "object") walk(v, e, file, inFunction);
}
for (const file of sources) {
  let ast = acorn.parse(fs.readFileSync(file, "utf8"), {
    ecmaVersion: "latest",
    sourceType: "module",
    locations: true,
  });
  walk(ast, new Map(), file);
}
const docs = ["av-core", "av-store", "av-daemon", "av-cli"].map((crate) => ({
  crate,
  file: `rust/crates/${crate}/PORTED.md`,
}));
const mappings = [];
const missingDocs = [];
for (let doc of docs) {
  let contents;
  if (fs.existsSync(doc.file)) contents = fs.readFileSync(doc.file, "utf8");
  else if (doc.crate === "av-cli") {
    try {
      contents = cp.execFileSync(
        "git",
        [
          "show",
          `${process.env.AV_CLI_REF || "origin/ericuldall/rust-port-cli"}:${doc.file}`,
        ],
        { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] },
      );
      doc.ref = process.env.AV_CLI_REF || "origin/ericuldall/rust-port-cli";
    } catch {
      missingDocs.push(doc);
      continue;
    }
  } else {
    missingDocs.push(doc);
    continue;
  }
  let current = null;
  let lineNo = 0;
  for (let line of contents.split("\n")) {
    lineNo++;
    if (line.startsWith("#") && line.includes("test/")) {
      let a = line.indexOf("test/"),
        b = line.indexOf(".test.js", a);
      if (b >= 0) current = line.slice(a, b + 8);
    }
    if (!line.startsWith("| ")) continue;
    let cols = line.slice(2, -2).split(" | ");
    if (cols[0].includes(".test.js")) {
      if (cols.length === 2 && cols[0].startsWith("`test/")) {
        let end = cols[0].indexOf(".test.js`") + 8;
        let file = cols[0].slice(1, end);
        let name = cols[0].slice(end + 1).trim();
        mappings.push({
          crate: doc.crate,
          doc: doc.file,
          ref: doc.ref,
          line: lineNo,
          file,
          name,
          status: cols[1],
        });
        continue;
      }
      let key = cols[0].replaceAll("`", "").trim();
      let file = key.startsWith("test/")
        ? key
        : sources.find((f) => path.basename(f) === key);
      if (file && cols.length >= 3)
        mappings.push({
          crate: doc.crate,
          doc: doc.file,
          line: lineNo,
          file,
          name: cols[1],
          status: cols.slice(2).join(" | "),
        });
    } else if (
      current &&
      cols.length >= 2 &&
      cols[0] !== "JS test" &&
      !cols[0].startsWith("---")
    )
      mappings.push({
        crate: doc.crate,
        doc: doc.file,
        line: lineNo,
        file: current,
        name: cols[0],
        status: cols.slice(1).join(" | "),
      });
  }
}
const mdName = (s) => {
  let o = "";
  for (let i = 0; i < s.length; i++) {
    let c = s.charCodeAt(i + 1);
    if (
      s[i] === "\\" &&
      ((c >= 33 && c <= 47) ||
        (c >= 58 && c <= 64) ||
        (c >= 91 && c <= 96) ||
        (c >= 123 && c <= 126))
    )
      i++;
    o += s[i];
  }
  return o;
};
for (let m of mappings) m.name = mdName(m.name);
const key = (x) => `${x.file}\u0000${x.name}`;
const by = new Map();
for (let m of mappings) {
  let k = key(m);
  by.set(k, [...(by.get(k) ?? []), m]);
}
const unique = [...new Map(cases.map((c) => [key(c), c])).values()];
const missing = unique.filter((c) => !by.has(key(c)));
const duplicate = unique
  .filter((c) => (by.get(key(c)) ?? []).length > 1)
  .map((c) => ({ ...c, mappings: by.get(key(c)) }));
const report = {
  auditScript: fs.readFileSync(__filename, "utf8"),
  sourceFiles: sources.length,
  declaredCases: cases.length,
  uniqueCases: unique.length,
  missingDocs,
  unresolved,
  missing,
  duplicateMappings: duplicate,
  counts: { missing: missing.length, duplicate: duplicate.length },
  cases: unique,
  mappings,
  sourceDuplicateNames: unique.filter(
    (c) => cases.filter((other) => key(other) === key(c)).length > 1,
  ),
};
report.conflictingCoverageClaims = duplicate.filter(
  (x) =>
    x.mappings.some((m) => m.status.includes("not yet ported")) &&
    x.mappings.some(
      (m) =>
        m.status.includes("covered by conformance") ||
        m.status.includes("covered by av-daemon / av-cli and conformance"),
    ),
);
report.counts.conflictingCoverageClaims =
  report.conflictingCoverageClaims.length;
fs.writeFileSync(
  process.argv[2] || "/tmp/av-daemon-ported-audit.json",
  JSON.stringify(report, null, 2),
);
console.log(
  JSON.stringify(
    {
      files: report.sourceFiles,
      declared: cases.length,
      unique: unique.length,
      missing: missing.length,
      duplicate: duplicate.length,
      unresolved,
      conflictingCoverageClaims: report.counts.conflictingCoverageClaims,
      missingByFile: [...new Set(missing.map((x) => x.file))].map((f) => [
        f,
        missing.filter((x) => x.file === f).length,
      ]),
      missingDocs,
    },
    null,
    2,
  ),
);
