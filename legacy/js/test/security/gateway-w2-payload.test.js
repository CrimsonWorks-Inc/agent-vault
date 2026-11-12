import test from 'node:test'
import assert from 'node:assert/strict'
import { evaluatePayload, validatePayload, scanGraphQL, parseStrictJson } from '../../src/core/payload.js'
const refuses = (fn,rule) => assert.throws(fn,e => e.code === 'AV_POLICY_DENIED' && e.rule === rule)
const req = (value,extra={}) => ({body:Buffer.from(value),contentType:'application/json',...extra})
test('JSON constraints are strict, additive and pointer-aware', () => {
 const sets=[{json:{'/channel':{required:true,one_of:['C1']},'/a~1b/~0':{min:1,max:2},'/missing':{absent:true}}}]
 evaluatePayload(sets,req('{"channel":"C1","a/b":{"~":2}}'))
 refuses(()=>evaluatePayload(sets,req('{"channel":1}')),'payload:json:0:one_of')
 refuses(()=>evaluatePayload(sets,{}),'payload:json:0:required')
 refuses(()=>evaluatePayload([...sets,{json:{'/channel':{one_of:['C2']}}}],req('{"channel":"C1"}')),'payload:json:0:one_of')
 refuses(()=>evaluatePayload([...sets,{json:{'/channel':{one_of:['C2']}}}],req('{"channel":"C2"}')),'payload:json:0:one_of')
 refuses(()=>evaluatePayload(sets,req('{"channel":"C1"}',{contentType:'text/plain'})),'payload_content_type')
 evaluatePayload([],req('not json'))
})
test('JSON parser rejects duplicate decoded names, malformed input and excess depth',()=>{
 for (const s of ['{"a":1,"a":2}','{"a":1,"\\u0061":2}','{"x":{"a":1,"a":2}}']) refuses(()=>parseStrictJson(s),'payload_duplicate_key')
 for (const s of ['{"a":1,}','[1,]','01','1e999','"\\q"','true false']) refuses(()=>parseStrictJson(s),'payload_unparseable')
 refuses(()=>parseStrictJson('['.repeat(65)+'0'+']'.repeat(65)),'payload_depth')
 assert.equal(parseStrictJson('{"__proto__":2}').__proto__,2)
})
test('form/query refuse ambiguity and enforce strict names',()=>{
 refuses(()=>evaluatePayload([{query:{a:{}}}],{query:'a=1&%61=2'}),'payload_duplicate_key')
 refuses(()=>evaluatePayload([{form:{a:{}}}],req('a=1&a=2',{contentType:'application/x-www-form-urlencoded'})),'payload_duplicate_key')
 refuses(()=>evaluatePayload([{query_strict:true,query:{a:{}}}],{query:'b=2'}),'payload:query:0:strict')
 evaluatePayload([{form:{a:{one_of:['1']}}}],req('a=1',{contentType:'application/x-www-form-urlencoded; charset=utf-8'}))
 refuses(()=>evaluatePayload([{max_body_bytes:1}],req('12')),'payload_size')
})
test('payload validation rejects unknown keys and all malformed constraints',()=>{
 for(const x of [null,[],{extra:1},{json:{bad:{}}},{json:{'/a~2':{}}},{json:{'/a':{required:true,absent:true}}},{query:{a:{one_of:[{}]}}},{query:{a:{min:NaN}}},{max_body_bytes:-1},{graphql:{operations:['bogus']}}]) assert.ok(validatePayload(x).length)
 assert.deepEqual(validatePayload({graphql:{operations:['query'],deny_fields:['createDeployKey']}}),[])
 refuses(()=>evaluatePayload([{what:1}],{}),'payload_invalid')
})
const g={operations:['query'],deny_fields:['createDeployKey']}
test('GraphQL parses full operations, fragments, arguments and strings',()=>{
 scanGraphQL('query A($x: [Int!]! = [1,2]) @skip(if:false) { user(id:$x) { ...F ... on User { name } } } fragment F on User { x: id }',g)
 scanGraphQL('{ a(text:"mutation createDeployKey", block:""" mutation { createDeployKey } """) } # mutation{bad}',g)
 refuses(()=>scanGraphQL('query A {a} mutation B {b}',g),'payload:graphql:operation')
 refuses(()=>scanGraphQL('{ x: createDeployKey }',g),'payload:graphql:deny_field')
 for(const doc of ['query','query A {}','query A { a( }','query A { a } garbage','{ a(text:"unterminated) }','fragment X on User {a}','{ ... }','query($x:) {a}','query { a(arg: [1) }']) refuses(()=>scanGraphQL(doc,g),'graphql_unparseable')
 refuses(()=>scanGraphQL('{a'.repeat(65)+'}'.repeat(65),g),'graphql_unparseable')
 refuses(()=>scanGraphQL(' '.repeat(300*1024),g),'graphql_unparseable')
})
test('GraphQL request classification checks batches and persisted queries',()=>{
 const sets=[{graphql:g}]
 evaluatePayload(sets,{method:'GET',query:'query=%7Ba%7D',path:'/graphql'})
 evaluatePayload(sets,req('[{"query":"{a}"},{"query":"{b}"}]'))
 refuses(()=>evaluatePayload(sets,req('[{"query":"{a}"},{"query":"mutation{b}"}]')),'payload:graphql:operation')
 refuses(()=>evaluatePayload(sets,req('{"extensions":{"persistedQuery":{"sha256Hash":"test"}}}')),'graphql_persisted')
 refuses(()=>evaluatePayload(sets,{path:'/graphql'}),'graphql_unreadable')
 evaluatePayload(sets,{path:'/other'})
 refuses(()=>evaluatePayload(sets,req('{"query":"{a}","query":"{b}"}')),'payload_duplicate_key')
})
