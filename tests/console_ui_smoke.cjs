/* Exercise the application state/rendering in a minimal DOM, no browser/network. */
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
class Element {
 constructor(tag='div'){this.tagName=tag;this.children=[];this.listeners={};this.attrs={};this.style={};this.value='';this.checked=false;this.disabled=false;this.hidden=false;this._text='';this.className='';this.classList={toggle:(name,on)=>{const names=new Set(this.className.split(' ').filter(Boolean));on?names.add(name):names.delete(name);this.className=[...names].join(' ');}};}
 set textContent(value){this._text=String(value??'');this.children=[];} get textContent(){return this._text+this.children.map(c=>c.textContent).join(' ');}
 append(...els){for(const el of els){el.parent=this;this.children.push(el);}} replaceChildren(...els){this.children=[];this._text='';this.append(...els);}
 setAttribute(k,v){this.attrs[k]=String(v);} addEventListener(name,fn){this.listeners[name]=fn;}
 querySelectorAll(selector){let result=[];for(const child of this.children){if(matches(child,selector))result.push(child);result.push(...child.querySelectorAll(selector));}return result;}
 querySelector(selector){return this.querySelectorAll(selector)[0]||null;} remove(){if(this.parent)this.parent.children=this.parent.children.filter(c=>c!==this);}
 showModal(){this.open=true;}close(){this.open=false;}scrollIntoView(){}requestSubmit(){}click(){return this.onclick?.({target:this});}
}
function matches(el,selector){if(selector==='input:checked')return el.tagName==='input'&&el.checked;if(selector==='input')return el.tagName==='input';if(selector.startsWith('.'))return el.className.split(' ').includes(selector.slice(1));return false;}
const elements={};const html=fs.readFileSync('neesha/console/static/index.html','utf8');
for(const match of html.matchAll(/id="([^"]+)"/g))elements['#'+match[1]]=new Element();
const tabs=['overview','map','infrastructure','people','graph','operations','evidence','analysis'].map(name=>{const e=new Element('button');e.dataset={tab:name};return e;});
const modes=['deterministic','single','multi'].map(value=>{const e=new Element('input');e.value=value;return e;});modes[0].checked=true;
const data={runs:[],sources:[],runtime_providers:[{provider:'openai',ready:true,model:'explicit-model'},{provider:'anthropic',ready:true,model:'explicit-model'}],budget:{period:'2026-11',committed:'0',cap:'10'},job:{state:'idle'}};
const requests=[];
const context=vm.createContext({console,URL,Blob,setInterval:()=>0,setTimeout:()=>0,window:{scrollTo(){}},fixtures:data,
 document:{querySelector:s=>elements[s]||tabs.find(t=>s===`[data-tab=${t.dataset.tab}]`),querySelectorAll:s=>s==='[data-tab]'?tabs:s==='input[name=harness-mode]'?modes:[],createElement:tag=>new Element(tag),createElementNS:(_,tag)=>new Element(tag)},
 fetch:async(path,options={})=>{requests.push({path,options});return {ok:true,json:async()=>path==='/api/session'?{token:'session-fixture'}:data};}});
vm.runInContext(fs.readFileSync('neesha/console/static/app.js','utf8'),context);
(async()=>{
 await new Promise(resolve=>setImmediate(resolve));
 assert.match(elements['#harness-readiness'].textContent,/2 \/ 2/);
 assert.equal(elements['#harness-providers'].children.length,2);
 assert.ok(elements['#harness-providers'].children.every(c=>c.children[0].disabled));
 vm.runInContext("harnessMode='multi';harnessProviders=['openai','anthropic'];renderHarness();",context);
 assert.ok(elements['#harness-providers'].children.every(c=>!c.children[0].disabled));
 assert.throws(()=>vm.runInContext("validateHarness('multi',['openai'])",context),/two or three/);
 const email={run_id:'a'.repeat(32),company:'person@gmail.com',subject_kind:'email',seed:{kind:'email',normalized:'person@gmail.com'},status:'complete',stop_reason:'complete',facts:[{fact_id:'f1',source_record_id:'s1',attribute:'public.email.github.author_name',subject:'person@gmail.com',value:'Published author',source:'github',admiralty:'C3',confidence:'medium',flags:[]}],inferences:[],requirements:[],skipped:[],collection:[],scores:{commercial_fit:{score:99}},power_map:[]};
 context.emailFixture=email;
 vm.runInContext("brief=emailFixture;renderView();",context);
 assert.doesNotMatch(elements['#view'].textContent,/Commercial fit/);
 assert.match(elements['#view'].textContent,/Company fit and company security scores do not apply/);
 vm.runInContext("tab='people';renderView();",context);
 assert.match(elements['#view'].textContent,/Public email evidence/);
 assert.match(elements['#view'].textContent,/Published author/);
 assert.doesNotMatch(elements['#view'].textContent,/Account-registration observations/);
 vm.runInContext("askDelete('a'.repeat(32),'person@gmail.com')",context);
 assert.ok(elements['#delete-dialog'].open);
 assert.equal(elements['#delete-title'].textContent,'person@gmail.com');
 await elements['#confirm-delete'].onclick();
 const deletion=requests.find(r=>r.options.method==='DELETE');
 assert.equal(deletion.path,'/api/runs/'+'a'.repeat(32));
 assert.equal(deletion.options.headers['X-Workspace-Token'],'session-fixture');
 assert.equal(elements['#delete-dialog'].open,false);
 assert.ok(!html.includes('>F3<'), 'Brand mark should not use F3');
 assert.ok(!html.includes('Evidence. Context.'), 'Landing hero heading should be removed');
 assert.ok(!html.toLowerCase().includes('$1 cap'), 'HTML should not include $1 cap');
 assert.ok(html.includes('brand-dot'), 'Brand mark should use minimalist CSS dot');
 assert.ok(html.includes('id="toggle-batch-btn"'), 'Batch Queue toggle button should exist');
 assert.ok(html.includes('id="batch-panel"'), 'Batch ingestion panel should exist');
 assert.ok(html.includes('id="operator-team-key"'), 'Team passkey input should exist in operator dialog');
 vm.runInContext("showSource({fact_id:'f-piv',source_record_id:'s-piv',attribute:'dns.subdomain',subject:'example.com',value:'api.example.com',source:'crt.sh',admiralty:'B2',confidence:'high',flags:[]})",context);
 assert.ok(elements['#source-dialog'].open);
 assert.match(elements['#source-content'].textContent,/Pivot: Investigate api\.example\.com/);
 assert.match(elements['#source-content'].textContent,/Source Connection Lineage/i);
 vm.runInContext("tab='map';renderView();",context);
 assert.match(elements['#view'].textContent,/Offline vector Geo-IP & ASN topology map/);
 assert.match(elements['#view'].textContent,/Source Connection Chart/);
 assert.match(elements['#view'].textContent,/Export Maltego \(\.graphml\)/);
 vm.runInContext("tab='operations';renderView();",context);
 assert.match(elements['#view'].textContent,/Temporal Attack Surface Diff/);
 assert.match(elements['#view'].textContent,/Operation Cases/);
 assert.match(elements['#view'].textContent,/Import Partner Case Bundle/);
 assert.match(elements['#view'].textContent,/Analysis of Competing Hypotheses/);
 assert.match(elements['#view'].textContent,/Team Webhook & Continuous Delta Alerting/);
 vm.runInContext("openCmdK()",context);
 assert.ok(elements['#cmdk-dialog'].open);
 assert.equal(elements['#context-drawer'].hidden, false);
 vm.runInContext("openOperatorDialog()",context);
 assert.ok(elements['#operator-dialog'].open);
 console.log('Workspace UI state/render smoke checks passed.');
})().catch(error=>{console.error(error);process.exitCode=1;});
