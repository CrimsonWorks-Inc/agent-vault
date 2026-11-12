import {budgetLimit,intersect} from '../../../../../legacy/js/src/core/policy.js';
const state=b=>{const n=budgetLimit(b);return n===Infinity?{kind:'unlimited'}:n===null?{kind:'unreadable'}:{kind:'limit',limit:n}};
const budgets=[{},{limit:null},{limit:5},{limit:'5'},{limit:-1},{limit:1.5}];
console.log(JSON.stringify(budgets.map(budget=>({budget,state:state(budget),intersections:[[ {budget} ],[{budget},{budget:{limit:3}}],[{budget:{limit:3}},{budget}]].map(layers=>{const effective=intersect(layers);return{layers,budget:effective.budget,state:state(effective.budget)}})}))));
