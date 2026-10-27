import test from 'node:test'
import assert from 'node:assert/strict'
import { Scrubber, compileScrubPattern, SCRUB_PATTERN_CORPUS } from '../../src/core/scrub.js'
const extra = () => [{name:'acme',...compileScrubPattern('acme_[A-Za-z0-9]{20,80}')}]
const token = 'acme_'+'Z'.repeat(40)
test('restricted scrub grammar refuses dangerous or broad expressions',()=>{
 for(const s of ['(a+)+b','.*','a','[a-z]+','abc.*def+','abc\\1','abc(?=x)','abc$','abc[A-Z]{257}','abc|','abc|xy','disk-usage_by_repository_over_time','abc[[]']) assert.throws(()=>compileScrubPattern(s),e=>e.rule==='scrub_pattern',s)
 for(const s of ['abc_[0-9]{1,64}','abc\\d{2,20}','abc\\.xyz|def_[A-Z]{0,40}','acme_[A-Za-z0-9]{20,80}']) assert.ok(compileScrubPattern(s).re.global)
})
test('extra patterns are additive to stored secret and derived protections',()=>{
 const s=new Scrubber([{secret:'fixture-secret-value',label:'fixture'}],{extraPatterns:extra()})
 const result=s.scrub(token+' fixture-secret-value ghp_'+'Q'.repeat(30))
 assert.equal(result.redactions,3)
 assert.ok(!result.text.includes(token)); assert.ok(s.derivedSeen.has('acme')); assert.ok(s.derivedSeen.has('github'))
 for(const line of SCRUB_PATTERN_CORPUS) assert.equal(s.scrub(line).text,line)
})
test('extra patterns survive every stream chunk boundary',()=>{
 for(let cut=0;cut<=token.length;cut++) {
  const s=new Scrubber([],{extraPatterns:extra()}), stream=s.stream()
  const out=stream.push('prefix '+token.slice(0,cut))+stream.push(token.slice(cut)+' suffix '+'.'.repeat(150))+stream.flush()
  assert.ok(!out.includes(token),`cut ${cut}`); assert.equal(stream.redactions,1)
  assert.ok(s.derivedSeen.has('acme'))
 }
})
test('long custom tokens do not leak when bounded suffix spans stream windows',()=>{
 const s=new Scrubber([],{extraPatterns:[{name:'long',...compileScrubPattern('long_[A-Z]{200}')}]}), stream=s.stream()
 let out=''; for(const c of 'long_'+'Z'.repeat(200)) out+=stream.push(c)
 out+=stream.flush(); assert.equal(out,'[[av:derived]]')
})
test('invalid persisted compiled patterns fail closed',()=>{
 assert.throws(()=>new Scrubber([],{extraPatterns:[{name:'bad',re:/anything/g}]}),e=>e.code==='AV_UNSCANNABLE' && e.rule==='scrub_pattern_invalid')
})
test('escaped literal prefixes retain custom matches across chunks',()=>{
 const s=new Scrubber([],{extraPatterns:[{name:'escaped',...compileScrubPattern('ab\\|_[A-Z]{20,80}')}]})
 const st=s.stream(); let out=''
 for(const ch of 'ab|_'+ 'Q'.repeat(30)) out+=st.push(ch)
 out+=st.flush(); assert.equal(out,'[[av:derived]]')
})


test('bounded grammar refuses combinatorial repetition and accepts realistic shapes promptly', () => {
  for (const source of ['abc[a-z]{0,256}[a-z]{0,256}Z', 'abc' + 'a?'.repeat(20) + 'Z', 'abc' + '[a]{0,20}a'.repeat(10) + 'Z', 'abc[A-Z]+', 'abc[A-Z]*', 'abc[A-Z]{1,}', 'abc[A-Z]{1,2}?', 'abc[A-Z]{257}', 'abc\n[A-Z]{4}', 'abc[A-Z]{3,1}', 'abc[^Q]{0,256}[^Q]{256}Q', 'abc[a-z]{0,256}[a-z]{256}Q', 'abc[0-9]{1,5}[A-Z]{3}', 'abc[0-9]{0,5}\\d', 'abc[A-Z]{256}x[B-Z]{256}x', 'abc[A-Z]{2,9}x?']) {
    assert.throws(() => compileScrubPattern(source), e => e.rule === 'scrub_pattern')
  }
  for (const source of ['acme_[A-Za-z0-9]{32,40}', 'sk-live-[0-9a-f]{24}', 'tok\\.[A-Z]{4}-[0-9]{6}', 'abc[a-z]{0,256}Z', 'abc_[0-9]{1,64}', 'abc\\d{2,20}', 'abc\\.xyz|def_[A-Z]{0,40}', 'ab\\|_[A-Z]{20,80}', 'long_[A-Z]{200}', 'abc[A-Z]{250}x[B-Z]{250}x', 'tok_[A-Z]{4}-[0-9]{6,8}', 'abc_[a-z]{0,10}_end']) {
    const { re } = compileScrubPattern(source)
    const start = performance.now()
    re.test('abc' + 'a'.repeat(64 * 1024))
    assert.ok(performance.now() - start < 50, source)
  }
})

// C5: whatever the grammar accepts finishes 64 KiB of input that never
// matches in under 50 ms, including input shaped to make it try hardest:
// the prefix at every word boundary, followed by the longest run the
// variable quantifier could take.
test('every accepted pattern scans hostile input in under 50 ms', () => {
  // The realistic shapes, and the worst ones the rules still allow: the
  // longest exact run before the variable quantifier, the widest classes, a
  // literal tail, and many branches.
  const accepted = [
    'acme_[A-Za-z0-9]{32,40}', 'sk-live-[0-9a-f]{24}', 'tok_[A-Z]{4}-[0-9]{6,8}', 'abc_[a-z]{0,10}_end',
    'abc[^Q]{252}[^Q]{0,256}Q', 'abc[^Q]{128}[^Q]{128}[^Q]{0,249}QQQQ', 'abc[^Q]{0,256}QQQQQQQQQQQQQQQQ',
    'abc\\S{253}\\S{0,256}', 'abc[^ ]{0,256}Q|abd[^ ]{0,256}Q|abe[^ ]{0,256}Q|abf[^ ]{0,256}Q|abg[^ ]{0,256}Q|abh[^ ]{0,256}Q',
    'abc[^Q]{250}[^Q]{250}[^Q]{9}',
  ]
  const N = 64 * 1024
  const fill = (unit) => unit.repeat(Math.ceil(N / unit.length)).slice(0, N)
  for (const source of accepted) {
    const { re } = compileScrubPattern(source)
    const prefixes = source.split('|').map((b) => b.slice(0, 3))
    const hostile = [
      'x'.repeat(N),
      // The prefix at every word boundary, as densely as it can appear.
      fill(prefixes.map((p) => ' ' + p).join('')),
      fill(prefixes.map((p) => ' ' + p + '-').join('')),
      // The prefix, then a long run of what the classes accept.
      ...[100, 300, 520, 1100].map((run) => fill(' ' + prefixes[0] + 'a'.repeat(run))),
      ...[100, 300, 520].map((run) => fill(' ' + prefixes[0] + 'q'.repeat(run) + 'Q'.repeat(3))),
    ]
    for (const input of hostile) {
      re.lastIndex = 0
      const start = performance.now()
      re.test(input)
      const took = performance.now() - start
      assert.ok(took < 50, `${source} took ${took.toFixed(1)} ms`)
    }
  }
})

test('a stream that mentions a pattern prefix keeps flowing, and its holdback stays bounded', () => {
  const s = new Scrubber([], { extraPatterns: extra() })
  const stream = s.stream()
  let out = '', most = 0, pushed = 0
  const push = (text) => { pushed += text.length; out += stream.push(text); most = Math.max(most, pushed - out.length) }
  // The prefix as an ordinary word, then a lot of ordinary text after it.
  push('we use acme_ tooling here; ')
  for (let i = 0; i < 2000; i++) push('ordinary text that goes on and on. ')
  assert.ok(out.length > 60_000, 'the stream was held back instead of flowing')
  assert.ok(most < 4096, `held back ${most} characters`)
  out += stream.flush()
  assert.ok(out.startsWith('we use acme_ tooling here; '))
  assert.equal(stream.redactions, 0)
})

test('a custom token straddling every possible cut is redacted whole, in any chunking', () => {
  const body = `before ${token} middle ${token} after`
  for (let size = 1; size <= 23; size += 2) {
    const s = new Scrubber([], { extraPatterns: extra() })
    const stream = s.stream()
    let out = ''
    for (let i = 0; i < body.length; i += size) out += stream.push(body.slice(i, i + size))
    out += stream.flush()
    assert.ok(!out.includes('acme_Z'), `chunk ${size}: ${out}`)
    assert.equal(stream.redactions, 2, `chunk ${size}`)
  }
})
