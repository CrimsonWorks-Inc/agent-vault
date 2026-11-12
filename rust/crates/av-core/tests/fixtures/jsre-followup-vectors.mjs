import {compileScrubPattern} from '../../../../../legacy/js/src/core/scrub.js';
import {requestHash} from '../../../../../legacy/js/src/core/canon.js';
const probes=[];
// Refused patterns have no portable JavaScript result (inline modifiers vary by Node).
function add(source,text,{flags='',refuse=false,scalarException=false}={}) {let row={source,text,flags,refuse,scalarException};if(!refuse){try{row.js=new RegExp(source,flags).test(text)}catch{row.js=null}}probes.push(row)}
for(const text of ['a','é','\u0085','\n','\r','\u2028','\u2029','😀'])add('^.$',text,{scalarException:text==='😀'});
add('^\\.$','.'); add('^[.]$','.'); add('^.$','aa');
for(const source of ['sek[ab]ret','sek[a&b]ret','sek[a&&b]ret','sek[a~~b]ret','sek[a--z]ret'])for(const text of ['sekaret','sek&ret','sek~ret','ordinary'])add(source,text,{refuse:source.includes('--')});
for(const source of ['^(?i)k$','(?m)^k$','(?i:k)','(?-i)k','(?i)(?i)k'])add(source,'K',{refuse:true});
for(const text of ['k','K','K'])add('^k$',text,{flags:'i'});
add('^(?:k)$','k');add('^\\(\\?i\\)$','(?i)');add('^[(?i)]+$','(?i)');
const scrub=['abc\\S{2}','abc\\W{2}','abc\\D{2}','abc[\\S]{2}','abc[^Q]{2}','abc😀{2}','abc\\S?','abc\\d{2}','abc\\w{2}','abc\\s{2}','abc[A-Z]{2}','abc\\S','abc.*','sek[a--z]ret'].map(source=>{let ok=true,problem=null;try{compileScrubPattern(source)}catch(e){ok=false;problem=e.toProblem()}return{source,ok,problem,refuse:ok&&(/\\[SWD].*[?{]|\[\^|😀/.test(source))}});
const counted=['abcXY','abc😀','abcX'].map(text=>({text,match:new RegExp('abc\\S{2}').exec(text)?.[0]??null}));
const invalidProblem=(()=>{try{compileScrubPattern('sek[a--z]ret')}catch(e){return e.toProblem()}})();
const requests=[{method:'POST',host:'EXAMPLE.TEST',headers:[['Z','a'],['X','2'],['X','1']],credentials:['z:token','a:token']},{method:'POST',host:'EXAMPLE.TEST',headers:[['Z','a'],['X','2'],['X','1'],['\uffff','bmp'],['\u{10000}','astral']],credentials:['z:token','a:token','\u{10000}','\uffff']},{method:'POST',host:'EXAMPLE.TEST',headers:[['\uffff','a'],['\u{10000}','b'],['Z','a'],['X','2'],['X','1']],credentials:['z:token','\u{10000}:token','\uffff:token','a:token']}].map(input=>({input,hash:requestHash(input)}));
const guard=[...['regex::Regex::new("a")','regex::RegexSet::new(["a"])','regex::RegexSetBuilder::new(["a"])','regex::bytes::Regex::new("a")','use regex::Regex as R; R::new("a")','use regex::{RegexSet as R}; R::new(["a"])','use regex as r; r::Regex::new("a")','use ::regex as r; r::RegexSet::new(["a"])','extern crate regex as r;','use crate::jsre::Regex as R; R::new("a")','Regex \n :: new("a")'].map(source=>({source,bypass:true})),{source:'av_core::jsre::compile("a")',bypass:false}];
console.log(JSON.stringify({probes,scrub,counted,invalidProblem,requests,guard}));
