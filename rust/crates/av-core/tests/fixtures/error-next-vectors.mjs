import {deny} from '../../../../../src/core/errors.js';
const values=['agent-vault ph next test-fake',{cli:['agent-vault session create --cred <slug>'],mcp:{tool:'vault_request_session'}},{mcp:{tool:'vault_request_session'}},{cli:['agent-vault ph next test-fake'],mcp:{tool:'vault_next_placeholder',args:{cred:'test-fake',field:'token'}}},'',null,false,0];
console.log(JSON.stringify(values.map(next=>({code:'AV_SESSION_REQUIRED',next,problem:deny('AV_SESSION_REQUIRED','test refusal',{next}).toProblem()}))));
