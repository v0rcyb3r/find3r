'use strict';
const $ = (s) => document.querySelector(s);
const text = (tag, value, cls) => { const el = document.createElement(tag); el.textContent = value ?? ''; if (cls) el.className = cls; return el; };
let session = '', snapshot = null, brief = null, tab = 'overview', selectedRun = null, polling = false;
let harnessMode = 'deterministic', harnessProviders = [], deleteTarget = null;
const date = (value) => { const d = new Date(value?.replace(' ', 'T')); return Number.isNaN(d.valueOf()) ? 'Time unavailable' : d.toLocaleString(undefined, {month:'short', day:'2-digit', hour:'2-digit', minute:'2-digit'}); };
async function api(path, options = {}) {
  const response = await fetch(path, {cache:'no-store', ...options});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'The workspace could not complete this request.');
  return data;
}
function message(value, error = false) { $('#form-message').textContent = value; $('#form-message').classList.toggle('error', error); }
function setTab(value) { tab = value; document.querySelectorAll('[data-tab]').forEach(b => b.setAttribute('aria-selected', String(b.dataset.tab === value))); renderView(); }
function isEmailBrief(){ return brief?.subject_kind === 'email' || brief?.seed?.kind === 'email'; }
function subjectLabel(value=brief){ return value?.seed?.value || value?.seed?.normalized || (typeof value?.seed==='string'?value.seed:null) || value?.subject || value?.company || 'Investigation'; }
function isRegistration(fact){ return /registration|account_exists|account\.exist|signup|recovery|platform_usage/.test(fact.attribute); }
function sourceButton(fact) { const b = text('button', fact.admiralty + ' ↗', 'source-button'); b.setAttribute('aria-label', `View source for ${fact.attribute}: ${fact.value}`); b.onclick = () => showSource(fact); return b; }
function showSource(fact) {
  const root = $('#source-content'); root.replaceChildren(text('h2', fact.attribute));
  const dl = document.createElement('dl');
  for (const [label, value] of Object.entries({Subject:fact.subject, Observation:fact.value, Grade:fact.admiralty, Confidence:fact.confidence, Flags:(fact.flags||[]).join(', ') || 'none', Source:fact.source, 'Evidence class':isRegistration(fact)?'Account-registration probe observation':'Public-source observation', 'Collected at':fact.collected_at, Mode:fact.collection_mode, 'Retrieved by':fact.retrieved_by||fact.source, 'Fact ID':fact.fact_id, 'Source record':fact.source_record_id, 'Payload SHA-256':fact.raw_sha256})) {
    dl.append(text('dt', label), text('dd', value));
  }
  const dd = document.createElement('dd');
  try { const url = new URL(fact.source_url); if (!['https:','http:'].includes(url.protocol)) throw Error(); const a = text('a', fact.source_url); a.href = url.href; a.target = '_blank'; a.rel = 'noopener noreferrer'; dd.append(a); } catch { dd.textContent = 'No available source URL'; }
  dl.append(text('dt', 'Source URL'), dd); root.append(dl); $('#source-dialog').showModal();
}
function empty(title, body) { const el = document.createElement('div'); el.className='empty'; el.append(text('span','＋','empty-cross'), text('h3',title), text('p',body)); return el; }
function table(facts) {
  if (!facts.length) return empty('No observations in this view.', 'A missing observation is an information gap, not proof of a security issue.');
  const wrap = document.createElement('div'); wrap.className = 'panel table-wrap';
  const t = document.createElement('table'); t.className = 'fact-list'; const head = document.createElement('thead'); const tr = document.createElement('tr');
  ['OBSERVATION','VALUE','CONFIDENCE','RECORD'].forEach(v => tr.append(text('th',v))); head.append(tr); t.append(head);
  const body = document.createElement('tbody');
  facts.forEach(f => { const r=document.createElement('tr'); const a=text('td',f.attribute + ((brief.inferences||[]).some(i=>i.fact_id===f.fact_id)?' · INFERENCE':'')); a.append(text('div',f.subject,'subject')); r.append(a, text('td',f.value), text('td',f.confidence)); const cell=document.createElement('td'); cell.append(sourceButton(f)); r.append(cell); body.append(r); });
  t.append(body); wrap.append(t); return wrap;
}
function panel(title) { const root = document.createElement('section'); root.className='panel'; const heading=text('div',null,'panel-title'); heading.append(text('h2',title)); const body=text('div',null,'panel-body'); root.append(heading,body); return {root,body}; }
function renderView() {
  if (!brief) return;
  const view = $('#view'); view.replaceChildren();
  if(tab==='graph'){ renderGraph(view); return; }
  if(tab==='analysis'){ renderAnalysis(view); return; }
  if (tab === 'infrastructure' && isEmailBrief()) { view.append(text('p','Domain context describes the mail provider. It does not establish the email owner’s cybersecurity posture, employer, or account security.','notice email-context'),table(brief.facts.filter(f=>/^(email\.domain|email\.syntax|dns)\./.test(f.attribute)))); return; }
  if (tab === 'infrastructure') { view.append(text('p','Certificate-transparency observations may be historical. A discovered hostname does not establish current reachability or vulnerability.','notice'),table(brief.facts.filter(f => /^(dns|tls|http|ip|discovery|email\.(dmarc|spf))\./.test(f.attribute)))); return; }
  if (tab === 'evidence') { view.append(text('p','Source-backed observations. Select a grade to inspect the underlying record and original collection time.','notice'),table([...brief.facts,...brief.inferences])); return; }
  if (tab === 'people' && isEmailBrief()) { view.append(text('p','Public associations must be linked by the exact email address. A public mention or account-registration observation does not establish a real-world identity, employment, or buying authority.','notice email-context')); const publicFacts=brief.facts.filter(f=>!isRegistration(f)&&/^(public|email\.public|person)\./.test(f.attribute)); const registrations=brief.facts.filter(isRegistration);view.append(text('h2','Public email evidence'),table(publicFacts));if(registrations.length)view.append(text('h2','Account-registration observations'),text('p','These observations come from interactions with platform registration or recovery endpoints, not passive public mentions. Errors and blocked probes remain unknown.','notice'),table(registrations));return; }
  if (tab === 'people') {
    const people = new Map(); brief.facts.filter(f => f.attribute.startsWith('person.')).forEach(f => { const key=f.entity_id||f.subject;if(!people.has(key)) people.set(key,[]); people.get(key).push(f); });
    const published = brief.facts.filter(f=>f.attribute.startsWith('company.business_') || f.attribute==='company.contact_page');
    if(published.length){view.append(text('h2','Published company contacts'),text('p','Business contact details published by the company. Generic inboxes are not assigned to a named person.','notice'),table(published));}
    if (!people.size) { view.append(empty('No named professional roles observed.', 'Free company-page extraction found no verifiable named staff in the pages it could read. A company may publish generic contacts without publishing its staff.')); }
    else { const grid=text('div',null,'people-grid'); for(const [identity,facts] of people){ const name=facts[0].subject; const card=text('article',null,'person'); card.append(text('div','BUSINESS CONTACT','eyebrow'),text('h3',name)); facts.forEach(f => { card.append(text('p',`${f.attribute.replace('person.','').replaceAll('_',' ')} · ${f.value}`),sourceButton(f)); }); grid.append(card); } view.append(grid); }
    const roles=brief.power_map||[];
    if(roles.length){const box=panel('Possible professional involvement · inferred');roles.forEach(r=>{const item=text('div',null,'requirement');item.append(text('h3',r.subject+' · '+r.possible_involvement.join(' / ')),text('p',r.rationale),text('span','LOW CONFIDENCE · TITLE-BASED INFERENCE','status warning'));box.body.append(item);});view.append(box.root);}
    view.append(text('p','Published roles are observations. Possible involvement is an inference; no buying authority or reporting line is established.','notice')); return;
  }
  if(!isEmailBrief()) renderScores(view);
  else view.append(text('p','Email-focused investigation. Company fit and company security scores do not apply. Public-source associations are observations, not verified identity or ownership.','notice email-context'));
  const grid=text('div',null,'overview-grid'); const requirements=panel('Intelligence requirements');
  brief.requirements.forEach(r => { const item=text('div',null,'requirement'); item.append(text('span',r.status,'status '+(r.status==='answered'?'':'warning')),text('h3',r.question)); item.append(text('p',r.gap_reason || `${r.fact_ids.length} supporting observations. Review the evidence before drawing conclusions.`)); requirements.body.append(item); });
  if (!brief.requirements.length) requirements.body.append(text('p','No requirements were recorded.','notice'));
  grid.append(requirements.root); const coverage=panel('Collection coverage');
  const sources=[...new Set(brief.facts.map(f=>f.source))]; coverage.body.append(text('div',sources.join(' / ') || 'No exportable source records','mono'),text('p',isEmailBrief()?'Collection follows this email as an independent subject. Read each source outcome below; mail-provider infrastructure is shown only as domain context.':'Free collection combines public company pages, DNS, certificate transparency, archives, and other enabled sources. Historical sightings do not establish current ownership or exposure.','notice'));
  (brief.collection||[]).forEach(s => coverage.body.append(text('p',`${s.source} · ${s.outcome} · ${s.facts} observations${s.activity_class?' · '+s.activity_class:''}`, 'notice')));
  brief.skipped.forEach(s => coverage.body.append(text('p',`${s.adapter}: ${s.reason}`,'notice warning')));
  coverage.body.append(text('p','All assertions pass an accuracy gate. Expired and non-business records are withheld.','notice')); grid.append(coverage.root); view.append(grid);
  const harnessSummary=panel('Agent Harness');const analysis=brief.model_analysis;harnessSummary.body.append(text('span',analysis?`${analysis.mode.toUpperCase()} · ${analysis.status.toUpperCase()}`:'DETERMINISTIC · NO MODEL ANALYSIS','status'),text('p',analysis?`${analysis.reports?.length||0} worker outcomes recorded. Conclusions remain cited inferences for human review.`:'Source collection and evidence rules produced this brief. No model analysis is attached to this investigation.','notice'));const review=text('button',analysis?'Review worker rollout ↗':'Open Agent Harness ↗','secondary');review.onclick=()=>setTab('analysis');harnessSummary.body.append(review);view.append(harnessSummary.root);
  if((brief.inferences||[]).length) { view.append(text('h2','Labeled inferences')); view.append(table(brief.inferences)); }
}
async function openRun(id) {
  selectedRun=id; $('#landing').hidden=true; $('#detail').hidden=false; $('#view').replaceChildren(text('p','Loading source records…','loading'));
  try { const loaded=await api(`/api/runs/${encodeURIComponent(id)}`); if(selectedRun!==id)return; brief=loaded; $('#company-title').textContent=subjectLabel(); $('#subject-kind').textContent=isEmailBrief()?'EMAIL INTELLIGENCE':'COMPANY INTELLIGENCE'; $('[data-tab=people]').textContent=isEmailBrief()?'Public associations':'People & roles'; $('[data-tab=infrastructure]').textContent=isEmailBrief()?'Domain context':'Infrastructure'; $('#delete-run').disabled=brief.status==='running'; $('#run-meta').textContent=`${brief.status.toUpperCase()} / ${brief.run_id.slice(0,12)} / ${brief.stop_reason}`;
    const metrics=$('#metrics'); metrics.replaceChildren();
    const hosts = new Set(brief.facts.filter(f=>['dns.subdomain','discovery.subdomain'].includes(f.attribute)).map(f=>f.value)).size;
    const people=new Set(brief.facts.filter(f=>f.attribute.startsWith('person.')).map(f=>f.subject)).size;
    const metricRows = isEmailBrief() ? [['PUBLIC OBSERVATIONS',brief.facts.filter(f=>/^(public|email\.public)\./.test(f.attribute)&&!isRegistration(f)).length,'Exact-email public evidence'],['REGISTRATION OBSERVATIONS',brief.facts.some(isRegistration)?brief.facts.filter(isRegistration).length:'—',brief.facts.some(isRegistration)?'Platform endpoint observations':'No registration checks in this run'],['OBSERVATIONS',brief.facts.length,'Includes domain context'],['OPEN REQUIREMENTS',brief.requirements.filter(r=>r.status!=='answered').length,'Unanswered or partial']] : [['HOSTNAMES',hosts,'Public-source hostname observations'],['BUSINESS CONTACTS',people,'Observed professional contacts'],['OBSERVATIONS',brief.facts.length,'Source-backed assertions'],['OPEN REQUIREMENTS',brief.requirements.filter(r=>r.status!=='answered').length,'Unanswered or partial']];
    for(const [label,value,note] of metricRows) { const el=text('div',null,'metric'); el.append(text('span',label,'eyebrow'),text('strong',String(value).padStart(2,'0')),text('small',note)); metrics.append(el); }
    setTab('overview'); window.scrollTo(0,0);
  } catch(e){ $('#view').replaceChildren(empty('Could not open investigation.',e.message)); }
}
function goHome(){ selectedRun=null;brief=null;$('#landing').hidden=false;$('#detail').hidden=true;refresh(); }
async function refresh() {
  try { snapshot=await api('/api/workspace'); const list=$('#runs'); list.replaceChildren(); $('#run-count').textContent=String(snapshot.runs.length).padStart(2,'0');
    if(!snapshot.runs.length) list.append(empty('A clear starting point.','Your investigations will appear here. Enter a domain or email above to begin.'));
    snapshot.runs.forEach(r=>{ const item=text('div',null,'run-item');const row=text('button',null,'run-row');const label=subjectLabel(r);row.append(text('span',r.subject_kind==='email'?'@':'⌘','run-icon'),text('span',label,'run-name'),text('span',date(r.started_at),'run-date'),text('span',r.status,'status'),text('span','↗')); row.onclick=()=>openRun(r.id);const remove=text('button','Delete','danger-button');remove.setAttribute('aria-label','Delete stored investigation '+label);remove.disabled=r.status==='running';remove.onclick=()=>askDelete(r.id,label);item.append(row,remove);list.append(item); });
    $('#budget').textContent=`${snapshot.budget.period} · $${Number(snapshot.budget.committed).toFixed(2)} / $${Number(snapshot.budget.cap).toFixed(2)} BUDGET`;
    renderCatalog(snapshot.sources||[]); renderHarness(); renderRollout(snapshot.job);
    const job=snapshot.job; $('#launch').disabled=['running','analyzing'].includes(job.state); $('#launch').textContent=['running','analyzing'].includes(job.state)?'Collecting…':'Investigate ↗';
    if(job.phase==='analysis'&&['running','analyzing'].includes(job.state)) message(`Analyzing cited evidence for ${job.domain||'subject'} · ${job.analysis_mode||'selected models'}. Collection has finished.`);
    else if(['running','analyzing'].includes(job.state)) message(`Investigating ${job.seed?.value||job.seed?.normalized||job.domain||'subject'} · ${job.current_source||'preparing collection'} · ${job.completed||0}/${job.total||'…'} sources completed`);
    if(polling&&!['running','analyzing'].includes(job.state)){ polling=false; if(job.state==='complete'){message(`Investigation finished for ${job.seed?.value||job.seed?.normalized||job.domain||'subject'}: ${job.observations||0} observations, ${job.sources_with_gaps||0} source gaps. Review coverage for details.`); await openRun(job.run_id);} else if(job.state==='failed')message(job.error,true); }
  } catch(e){ message(e.message,true); }
}
$('#investigate').addEventListener('submit',async e=>{e.preventDefault();$('#launch').disabled=true;try { validateHarness(harnessMode,harnessProviders);const seed=$('#domain').value;const email=seed.includes('@'); const result=await api('/api/investigations',{method:'POST',headers:{'Content-Type':'application/json','X-Workspace-Token':session},body:JSON.stringify({domain:seed,contacts:!email&&$('#contacts').checked,website:!email&&$('#website').checked,analysis_mode:harnessMode,providers:harnessMode==='deterministic'?[]:harnessProviders})}); polling=true; message(`Starting investigation for ${result.seed?.value||result.seed?.normalized||result.domain||seed}…`); await refresh(); }catch(err){message(err.message,true);$('#launch').disabled=false;}});
$('#back').onclick=goHome;$('#home').onclick=goHome;$('#close-source').onclick=()=>$('#source-dialog').close();
document.querySelectorAll('[data-tab]').forEach(b=>b.onclick=()=>setTab(b.dataset.tab));
$('#export').onclick=()=>{if(!brief)return;const url=URL.createObjectURL(new Blob([JSON.stringify(brief,null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download=`neesha-${brief.run_id}.json`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);};
function clock(){ $('#clock').textContent=new Date().toISOString().slice(11,19)+' UTC'; }clock();setInterval(clock,1000);
(async()=>{try{session=(await api('/api/session')).token;await refresh();polling=['running','analyzing'].includes(snapshot?.job.state);}catch(e){message(e.message,true);}})();setInterval(()=>{if(polling)refresh();},1800);


function validateHarness(mode,providers){
 if(mode==='deterministic')return;
 const ready=new Set((snapshot?.runtime_providers||[]).filter(p=>p.ready).map(p=>p.provider));
 if(providers.some(p=>!ready.has(p)))throw new Error('Choose configured runtime providers.');
 if(mode==='single'&&providers.length!==1)throw new Error('Select one provider for single-model analysis.');
 if(mode==='multi'&&(providers.length<2||providers.length>3))throw new Error('Select two or three providers for multi-model analysis.');
}
function renderHarness(){
 const providers=snapshot?.runtime_providers||[],ready=providers.filter(p=>p.ready);
 $('#harness-readiness').textContent=`${ready.length} / ${providers.length} PROVIDERS CONFIGURED`;
 const root=$('#harness-providers');root.replaceChildren();
 providers.forEach(p=>{const label=text('label',null,'provider-choice');const input=document.createElement('input');input.type='checkbox';input.value=p.provider;input.checked=harnessProviders.includes(p.provider);input.disabled=!p.ready||harnessMode==='deterministic';input.setAttribute('aria-label','Use '+p.provider+' for model analysis');const description=text('span');description.append(text('strong',p.provider),text('small',p.model||'No model configured'),text('small',p.ready?'Configured · account access not tested':p.reason||'Not configured'));label.append(input,description);input.onchange=()=>{if(harnessMode==='single')harnessProviders=input.checked?[p.provider]:[];else harnessProviders=input.checked?[...harnessProviders,p.provider]:harnessProviders.filter(n=>n!==p.provider);renderHarness();};root.append(label);});
 document.querySelectorAll('input[name=harness-mode]').forEach(input=>{input.disabled=input.value==='single'?!ready.length:input.value==='multi'&&ready.length<2;input.checked=input.value===harnessMode;input.onchange=()=>{harnessMode=input.value;if(harnessMode==='single'&&harnessProviders.length>1)harnessProviders=harnessProviders.slice(0,1);renderHarness();};});
 $('#harness-note').textContent=harnessMode==='deterministic'?'Deterministic mode: source collection and evidence rules. No runtime model calls or model fees.':harnessMode==='single'?'Select one configured provider. It receives eligible cited facts after collection, including public email/profile evidence when applicable. Analysis is capped at $1.':'Select two or three configured providers. Two specialists analyze separate evidence; a reviewer checks their proposals against the sources. Up to three calls, $1 total cap. Eligible facts go to those providers.';
}
function renderRollout(job){
 const root=$('#harness-rollout');root.replaceChildren();if(!job||job.state==='idle')return;
 const rollout=text('div',null,'rollout');const running=['running','analyzing'].includes(job.state),analyzing=job.state==='analyzing'||job.phase==='analysis';
 const steps=[['Collection',running&&!analyzing?`${job.current_source||'Preparing sources'} · ${job.completed||0}/${job.total||'…'}`:analyzing?'Source collection finished':job.state==='complete'?'Finished; review source outcomes':job.state],['Evidence gate',analyzing||job.state==='complete'?'Guarded evidence available':'Applied as observations are processed'],['Analysis',analyzing?'Selected model analysis running':job.state==='complete'?'Open the investigation to review its analysis mode and outcomes':harnessMode==='deterministic'?'Deterministic · no model calls':'Selected models run after collection']];
 steps.forEach(([name,detail],i)=>{const item=text('div',null,'rollout-step'+(running&&((i===0&&!analyzing)||(i===2&&analyzing))?' running':''));item.append(text('strong',name),text('p',detail));rollout.append(item);});root.append(rollout);
}
function askDelete(id,label){deleteTarget={id,label};$('#delete-title').textContent=label;$('#delete-message').textContent='';$('#delete-dialog').showModal();}
$('#delete-run').onclick=()=>{if(brief)askDelete(brief.run_id,subjectLabel());};
$('#close-delete').onclick=()=>$('#delete-dialog').close();$('#cancel-delete').onclick=()=>$('#delete-dialog').close();
$('#confirm-delete').onclick=async()=>{if(!deleteTarget)return;const target=deleteTarget;$('#confirm-delete').disabled=true;
 try{const result=await api(`/api/runs/${encodeURIComponent(target.id)}`,{method:'DELETE',headers:{'X-Workspace-Token':session}});$('#delete-dialog').close();deleteTarget=null;if(selectedRun===target.id)goHome();else await refresh();const incomplete=result.report_cleanup_failures?.length||result.journal_checkpointed===false;message(incomplete?'Investigation records deleted; some report files or database journal cleanup could not finish. Check local storage permissions.':`Deleted stored investigation for ${target.label}.`,Boolean(incomplete));}catch(error){$('#delete-message').textContent=error.message;}finally{$('#confirm-delete').disabled=false;}};
$('#harness-nav').onclick=()=>{if(brief)setTab('analysis');else $('#harness-config').scrollIntoView({behavior:'smooth'});};
$('#domain').addEventListener('input',()=>{const email=$('#domain').value.includes('@');$('#seed-notice').hidden=!email;$('#website').disabled=email;$('#contacts').disabled=email;});

function renderCatalog(sources){
 const root=$('#source-catalog');root.replaceChildren();
 const available=sources.filter(s=>s.ready&&s.tier==='A').length;
 $('#source-count').textContent=`${available} FREE SOURCES AVAILABLE`;
 sources.forEach(s=>{const card=text('div',null,'source-card');const registration=/holehe|socialscan|registration|recovery/i.test(s.name);const category=registration?'ACCOUNT REGISTRATION / RECOVERY PROBES':s.mode==='third_party_passive'?'EXISTING PUBLIC / PROVIDER DATA':s.mode==='direct_contact'?'DIRECT PUBLIC WEBSITE READ':s.mode==='active'?'ACTIVE COLLECTION':'MODULE-DEPENDENT';card.append(text('h3',s.name),text('div',category,'source-category'),text('p',s.state,'status '+(s.ready?'':'warning')),text('p',s.description,'notice'));if(!s.ready)card.append(text('p',s.reason,'notice'));root.append(card);});
}

function renderScores(view){
 if(!brief.scores)return;const grid=text('div',null,'score-grid');
 for(const [key,label] of [['commercial_fit','Commercial fit'],['security_needs','Evidence of potential security needs']]){
  const score=brief.scores[key];const box=panel(label);box.body.append(text('strong',score.score===null?'—':String(score.score),'score-value'),text('span',score.score===null?'UNASSESSED':' / 100','eyebrow'),text('p',`${score.coverage}% weighted criterion coverage · ${score.assessed_count}/${score.criteria_count} assessed`,'mono muted'),text('p',score.explanation,'notice'));
  const details=document.createElement('details');details.append(text('summary','Weights, evidence & unknowns'));
  score.criteria.forEach(c=>{const row=text('div',null,'requirement');row.append(text('h3',`${c.label} · weight ${c.weight} · ${c.status}`),text('p',c.explanation));if(c.contribution!==null)row.append(text('p',`Score contribution: ${c.contribution}`,'mono muted'));c.evidence_ids.forEach(id=>{const f=brief.facts.find(f=>f.fact_id===id);if(f)row.append(sourceButton(f));});details.append(row);});
  box.body.append(details);grid.append(box.root);
 }view.append(grid);
}
function renderGraph(view){
 const graph=brief.graph;if(!graph){view.append(empty('No graph available.','Reopen a completed investigation to build its evidence graph.'));return;}
 view.append(text('p',graph.identity_policy+' '+graph.context,'notice'));
 const categories=['organization','domain','person','email','account','phone','ip','url','observation'];
 const NODE_W=300,COL=NODE_W+60,ROW=75,MAXLEN=40;
 const all=graph.nodes;const shown=all.filter(n=>n.kind!=='observation').slice(0,55);const positions=new Map();const columns=new Map();
 categories.forEach(k=>columns.set(k,[]));shown.forEach(n=>columns.get(n.kind)?.push(n));
 const ns='http://www.w3.org/2000/svg';const svg=document.createElementNS(ns,'svg');const nonempty=categories.filter(k=>columns.get(k).length);const width=Math.max(1000,30+nonempty.length*COL);let height=440;
 nonempty.forEach((kind,i)=>{const group=columns.get(kind);height=Math.max(height,group.length*ROW+100);group.forEach((n,j)=>positions.set(n.id,{x:30+i*COL,y:65+j*ROW}));});
 svg.setAttribute('viewBox',`0 0 ${width} ${height}`);svg.setAttribute('role','img');svg.setAttribute('aria-label','Source-backed entity relationships');svg.style.minWidth=width+'px';
 graph.edges.forEach(edge=>{const a=positions.get(edge.source),b=positions.get(edge.target);if(!a||!b)return;const path=document.createElementNS(ns,'path');const x1=a.x+NODE_W,y1=a.y+18,x2=b.x,y2=b.y+18;path.setAttribute('d',`M${x1},${y1} C${x1+45},${y1} ${x2-45},${y2} ${x2},${y2}`);path.setAttribute('class','graph-edge');const title=document.createElementNS(ns,'title');title.textContent=edge.kind+' · '+edge.evidence_ids.length+' source-backed observations';path.append(title);svg.append(path);});
 nonempty.forEach((kind,i)=>{const title=document.createElementNS(ns,'text');title.setAttribute('x',30+i*COL);title.setAttribute('y',30);title.setAttribute('class','graph-label');title.textContent=kind.toUpperCase();svg.append(title);});
 shown.forEach(node=>{const p=positions.get(node.id);const g=document.createElementNS(ns,'g');g.setAttribute('transform',`translate(${p.x},${p.y})`);const rect=document.createElementNS(ns,'rect');rect.setAttribute('width',NODE_W);rect.setAttribute('height',38);rect.setAttribute('class','graph-node');const label=document.createElementNS(ns,'text');label.setAttribute('x',12);label.setAttribute('y',24);label.setAttribute('class','graph-node-label');label.textContent=node.label.length>MAXLEN?node.label.slice(0,MAXLEN-1)+'…':node.label;const title=document.createElementNS(ns,'title');title.textContent=node.label;g.append(rect,label,title);svg.append(g);});
 const canvas=text('div',null,'panel graph-canvas');canvas.append(svg);view.append(canvas);
 if(shown.length<all.length)view.append(text('p',`Showing ${shown.length} entity nodes. Full graph: ${all.length} nodes, ${graph.edges.length} edges; all remain in JSON export.`,'notice'));
 const panelBox=panel('Relationships and supporting evidence');graph.edges.slice(0,100).forEach(e=>{const a=all.find(n=>n.id===e.source),b=all.find(n=>n.id===e.target);const row=text('div',null,'requirement');row.append(text('h3',`${a?.label} → ${e.kind} → ${b?.label}`));e.evidence_ids.forEach(id=>{const fact=brief.facts.find(f=>f.fact_id===id);if(fact)row.append(sourceButton(fact));});panelBox.body.append(row);});view.append(panelBox.root);
}
function renderAnalysis(view){
 const box=panel('Agent Harness');
 box.body.append(text('p','Source adapters collect the evidence. Deterministic rules organize it; selected models can add cited inferences. Models receive eligible facts, including public email/profile evidence when applicable. They cannot browse, use tools, or edit observations.','notice'));
 const available=(snapshot?.runtime_providers||[]).filter(p=>p.ready);
 const form=document.createElement('form');
 const mode=document.createElement('select');mode.setAttribute('aria-label','Agent harness analysis mode');
 for(const [value,label] of [['deterministic','Deterministic · no model calls'],['single','Single model · one cited synthesis'],['multi','Multi-model · specialists + reviewer']]){const option=text('option',label);option.value=value;option.disabled=value==='single'?!available.length:value==='multi'&&available.length<2;mode.append(option);}
 mode.value=harnessMode;
 const choices=text('div',null,'model-choices');
 available.forEach(p=>{const label=text('label',null,'contact-option');const input=document.createElement('input');input.type='checkbox';input.name='provider';input.value=p.provider;input.checked=harnessProviders.includes(p.provider);input.disabled=mode.value==='deterministic';label.append(input,text('span',p.provider+' · '+p.model));input.onchange=()=>{if(mode.value==='single'&&input.checked)choices.querySelectorAll('input').forEach(other=>{if(other!==input)other.checked=false;});};choices.append(label);});
 mode.onchange=()=>{choices.querySelectorAll('input').forEach(i=>i.disabled=mode.value==='deterministic');};
 const run=text('button','Run selected analysis · $1 cap','primary');run.type='submit';const status=text('p',available.length?'Every output remains tentative and requires human review.':'No runtime providers are ready. Configure a provider key, explicit model, and call cap on the server. Collection and deterministic views still work.','notice');
 form.append(mode,choices,run,status);
 form.onsubmit=async e=>{e.preventDefault();const providers=[...choices.querySelectorAll('input:checked')].map(i=>i.value);run.disabled=true;
 try{validateHarness(mode.value,providers);harnessMode=mode.value;harnessProviders=providers;renderHarness();
 if(mode.value==='deterministic'){status.textContent='Deterministic evidence views are ready. No model request was made.';return;}
 status.textContent='Running bounded analysis. Selected providers receive the eligible cited facts…';const runId=brief.run_id;
 const result=await api(`/api/runs/${runId}/analysis`,{method:'POST',headers:{'Content-Type':'application/json','X-Workspace-Token':session},body:JSON.stringify({mode:mode.value,providers})});
 if(brief?.run_id!==runId)return;brief.model_analysis=result;status.textContent=result.status==='complete'?'Analysis complete. Review the cited inferences.':result.reason||'Analysis finished with gaps. Review each worker outcome.';renderModelResult(box.body,result);
 }catch(err){status.textContent=err.message;}finally{run.disabled=false;}};
 box.body.append(form);view.append(box.root);if(brief.model_analysis)renderModelResult(box.body,brief.model_analysis);
}
function renderModelResult(root,result){
 root.querySelector('.model-result')?.remove();
 const container=text('div',null,'model-result analysis-results');
 const summary=text('div',null,'analysis-summary');summary.append(text('span',`${result.mode?.toUpperCase()||'ANALYSIS'} · ${result.status?.toUpperCase()||'UNKNOWN'}`,'mono'),text('span',`Conservative charge: $${Number(result.spend_usd||0).toFixed(4)}`,'mono muted'));container.append(summary);
 const reports=text('div',null,'rollout');(result.reports||[]).forEach(report=>{const item=text('div',null,'rollout-step');item.append(text('strong',report.role.replaceAll('_',' ')),text('p',`${report.provider} · ${report.model}`),text('p',`${report.status} · $${Number(report.cost_usd||0).toFixed(4)}`));if(report.reason)item.append(text('p',report.reason));reports.append(item);});container.append(reports);
 const box=panel('Cited model conclusions · inference, human review required');
 if(!(result.claims||[]).length)box.body.append(text('p',result.reason||'No validated conclusions were produced. This is not evidence that the subject has no relevant public information.','notice'));
 (result.claims||[]).forEach(claim=>{const item=text('div',null,'requirement');item.append(text('span','INFERENCE · HUMAN REVIEW REQUIRED','status warning'),text('h3',claim.text));(claim.evidence_ids||[]).forEach(id=>{const fact=brief.facts.find(f=>f.fact_id===id);if(fact)item.append(sourceButton(fact));});box.body.append(item);});container.append(box.root);root.append(container);
}

$('#export-report').onclick=()=>{
 if(!brief)return;
 const safe=v=>String(v??'').replace(/[\r\n]/g,' ').replace(/[<>]/g,c=>c==='<'?'&lt;':'&gt;').replace(/`/g,"'");
 const lines=[`# NEESHA · ${safe(subjectLabel())}`,'',`Run: ${brief.run_id}`,'','## Explained scores',''];
 for(const [key,label] of [['commercial_fit','Commercial fit'],['security_needs','Evidence of potential security needs']]){const s=isEmailBrief()?null:brief.scores?.[key];if(!s)continue;lines.push(`${label}: ${s.score===null?'unassessed':s.score+'/100'}; coverage ${s.coverage}%.`,s.explanation,'');s.criteria.forEach(c=>lines.push(`- ${safe(c.label)}: ${c.status}; weight ${c.weight}; contribution ${c.contribution??'unknown'}; evidence ${c.evidence_ids.join(', ')||'none'}. ${safe(c.explanation)}`));}
 lines.push('','## Observations and source records','');
 brief.facts.forEach(f=>lines.push(`- [${f.fact_id}] ${safe(f.subject)}: ${safe(f.attribute)} = ${safe(f.value)}`,`  Source: ${safe(f.source_url)}; collected ${safe(f.collected_at)}; retrieved by ${safe(f.retrieved_by||f.source)}; grade ${f.admiralty}; confidence ${f.confidence}; source record ${f.source_record_id}.`,''));
 lines.push('## Requirements and gaps','');brief.requirements.forEach(r=>lines.push(`- ${safe(r.question)}: ${r.status}. ${safe(r.gap_reason||'')}`));brief.skipped.forEach(s=>lines.push(`- ${safe(s.adapter)}: ${safe(s.reason)}`));
 if(brief.model_analysis){lines.push('','## Model analysis · tentative inferences for human review','');brief.model_analysis.claims.forEach(c=>lines.push(`- ${safe(c.text)} [${c.evidence_ids.join(', ')}]`));}
 const url=URL.createObjectURL(new Blob([lines.join('\n')],{type:'text/markdown;charset=utf-8'}));const a=document.createElement('a');a.href=url;a.download=`neesha-${brief.run_id}.md`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
};
