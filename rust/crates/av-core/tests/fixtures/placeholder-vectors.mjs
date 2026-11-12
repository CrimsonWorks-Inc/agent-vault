import {mint,hashNonce} from '../../../../../legacy/js/src/core/placeholder.js';
import {canonicalize,requestHash} from '../../../../../legacy/js/src/core/canon.js';
const kPh=Buffer.alloc(32,42);
console.log(JSON.stringify({key:[...kPh],vectors:Array.from({length:8},(_,i)=>mint({kPh,sid:'0123456789ab',slug:i===7?'a'.repeat(24):'test-fake',field:i===7?'b'.repeat(16):'token'})),nonceHash:hashNonce('0123456789abcdefghjkmnpqrs0'),canon:canonicalize({'é':1,a:[true,null,'fake']}),requestHash:requestHash({method:'post',host:'EXAMPLE.COM',path:'/x',headers:[['Z','a'],['X','2'],['X','1']],credentials:['b:token','a:token']})}));
