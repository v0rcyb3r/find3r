'use strict';
const $ = (s) => document.querySelector(s);
const text = (tag, value, cls) => { const el = document.createElement(tag); el.textContent = value ?? ''; if (cls) el.className = cls; return el; };
let session = '', snapshot = null, brief = null, tab = 'overview', selectedRun = null, polling = false;
let harnessMode = 'deterministic', harnessProviders = [], deleteTarget = null;
let graphZoom = 1, graphKindFilter = 'all', workspaceView = 'command';
let runSearchQuery = '', runKindFilter = 'all', operatorCallsign = 'local-analyst', teamPasskey = '';

function setWorkspaceView(viewName) {
  workspaceView = viewName;
  if (viewName !== 'command' && $('#detail') && !$('#detail').hidden) {
    selectedRun = null;
    brief = null;
    $('#detail').hidden = true;
    $('#landing').hidden = false;
  }
  const panels = {
    command: $('#ws-panel-command'),
    cloud: $('#cloud-config'),
    harness: $('#harness-config'),
    tools: $('#tools-config'),
  };
  Object.entries(panels).forEach(([k, el]) => {
    if (el) el.hidden = k !== viewName;
  });
  ['command', 'cloud', 'harness', 'tools'].forEach(k => {
    const tabBtn = $(`#ws-tab-${k}`);
    if (tabBtn) tabBtn.classList.toggle('active', k === viewName);
  });
  const railMap = {command: '#home', cloud: '#cloud-nav', harness: '#harness-nav', tools: '#tools-nav'};
  Object.entries(railMap).forEach(([k, sel]) => {
    const btn = $(sel);
    if (btn) {
      btn.classList.toggle('active', k === viewName);
      btn.setAttribute('aria-current', k === viewName ? 'page' : 'false');
    }
  });
}

const date = (value) => {
  const d = new Date(value?.replace(' ', 'T'));
  return Number.isNaN(d.valueOf()) ? 'Time unavailable' : d.toLocaleString(undefined, {month:'short', day:'2-digit', hour:'2-digit', minute:'2-digit'});
};

async function api(path, options = {}) {
  const mergedHeaders = {...(options.headers || {})};
  if (teamPasskey) mergedHeaders['X-Team-Key'] = teamPasskey;
  const fetchOpts = {cache: 'no-store', ...options};
  if (Object.keys(mergedHeaders).length) fetchOpts.headers = mergedHeaders;
  const response = await fetch(path, fetchOpts);
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'The workspace could not complete this request.');
  return data;
}

function message(value, error = false) {
  $('#form-message').textContent = value;
  $('#form-message').classList.toggle('error', error);
}

function setTab(value) {
  tab = value;
  document.querySelectorAll('[data-tab]').forEach(b => b.setAttribute('aria-selected', String(b.dataset.tab === value)));
  renderView();
}

function subjectKind(value = brief) {
  return value?.subject_kind || value?.seed?.kind || 'company';
}

function isEmailBrief() {
  return ['email', 'username', 'phone', 'person'].includes(subjectKind());
}

function isNonCompanyBrief() {
  return ['email', 'username', 'ip', 'phone', 'person'].includes(subjectKind());
}

function subjectLabel(value = brief) {
  return value?.seed?.value || value?.seed?.normalized || (typeof value?.seed === 'string' ? value.seed : null) || value?.subject || value?.company || 'Investigation';
}

function isRegistration(fact) {
  return /registration|account_exists|account\.exist|public\.account|signup|recovery|platform_usage/.test(fact.attribute);
}

function isPivotableValue(val, attr = '') {
  if (typeof val !== 'string') return false;
  const v = val.trim();
  if (!v || v.length > 180 || /\s/.test(v) || /^https?:\/\//i.test(v)) return false;
  if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v)) return true;
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(v)) return true;
  if (/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/i.test(v)) return true;
  if (/username|handle|subdomain|domain|email|ip|host/i.test(attr) && v.length >= 2) return true;
  return false;
}

function sourceButton(fact) {
  const b = text('button', (fact.admiralty || 'C3'), 'source-button');
  b.setAttribute('aria-label', `View source for ${fact.attribute}: ${fact.value}`);
  b.onclick = () => showSource(fact);
  return b;
}

function syncContextDrawer(titleText) {
  const drawer = $('#context-drawer');
  const drawerBody = $('#context-drawer-body');
  const splitLayout = $('#detail-split-layout');
  const srcContent = $('#source-content');
  if (!drawer || !drawerBody || !srcContent) return;
  if ($('#drawer-title') && titleText) {
    $('#drawer-title').textContent = titleText;
  }
  drawerBody.replaceChildren();
  const nodes = Array.from(srcContent.childNodes || srcContent.children || []);
  nodes.forEach(node => {
    drawerBody.append(node.cloneNode ? node.cloneNode(true) : node);
  });
  // Rebind interactive buttons inside the cloned drawer body
  const origBtns = srcContent.querySelectorAll('button');
  const clonedBtns = drawerBody.querySelectorAll('button');
  origBtns.forEach((btn, idx) => {
    if (clonedBtns[idx] && btn.onclick) {
      clonedBtns[idx].onclick = btn.onclick;
    }
  });
  drawer.hidden = false;
  if (splitLayout?.classList) {
    if (splitLayout.classList.add) splitLayout.classList.add('drawer-open');
    else if (splitLayout.classList.toggle) splitLayout.classList.toggle('drawer-open', true);
  }
}

function closeContextDrawer() {
  const drawer = $('#context-drawer');
  const splitLayout = $('#detail-split-layout');
  if (drawer) drawer.hidden = true;
  if (splitLayout?.classList) {
    if (splitLayout.classList.remove) splitLayout.classList.remove('drawer-open');
    else if (splitLayout.classList.toggle) splitLayout.classList.toggle('drawer-open', false);
  }
}

if ($('#toggle-drawer-btn')) {
  $('#toggle-drawer-btn').onclick = () => {
    const drawer = $('#context-drawer');
    if (!drawer) return;
    if (drawer.hidden) {
      drawer.hidden = false;
      const splitLayout = $('#detail-split-layout');
      if (splitLayout?.classList?.add) splitLayout.classList.add('drawer-open');
      else if (splitLayout?.classList?.toggle) splitLayout.classList.toggle('drawer-open', true);
    } else {
      closeContextDrawer();
    }
  };
}
if ($('#drawer-close-btn')) $('#drawer-close-btn').onclick = closeContextDrawer;
if ($('#drawer-modal-btn')) {
  $('#drawer-modal-btn').onclick = () => {
    $('#source-dialog')?.showModal();
  };
}

async function pinFactToOperations(fact) {
  if (!fact) return;
  try {
    const res = await api('/api/operations/pin', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', 'X-Workspace-Token': session},
      body: JSON.stringify({
        fact_id: fact.fact_id,
        run_id: brief?.run_id || '',
        subject: fact.subject || subjectLabel(),
        attribute: fact.attribute,
        value: fact.value,
        source: fact.source,
        admiralty: fact.admiralty || 'C3',
      }),
    });
    if (snapshot) snapshot.operations = res.operations;
    message(res.pinned ? `Pinned finding [${fact.attribute}] to Operations Pinboard.` : `Unpinned finding [${fact.attribute}].`);
    if (tab === 'operations') renderView();
  } catch (err) {
    message(err.message, true);
  }
}

async function expandEntityNodeInPlace(selectorValue) {
  if (!brief || !selectorValue) return;
  const target = String(selectorValue).trim().toLowerCase();
  let addedFacts = 0;
  const existingIds = new Set((brief.facts || []).map(f => f.fact_id));
  const runs = snapshot?.runs || [];
  for (const r of runs.slice(0, 12)) {
    if (r.id === brief.run_id) continue;
    try {
      const other = await api(`/api/runs/${encodeURIComponent(r.id)}`);
      const matching = (other.facts || []).filter(f =>
        !existingIds.has(f.fact_id) &&
        (String(f.subject || '').toLowerCase().includes(target) ||
         String(f.value || '').toLowerCase().includes(target))
      );
      matching.forEach(f => {
        existingIds.add(f.fact_id);
        brief.facts.push(f);
        addedFacts++;
      });
      if (matching.length && other.graph && brief.graph) {
        const nodeIds = new Set((brief.graph.nodes || []).map(n => n.id));
        (other.graph.nodes || []).forEach(n => {
          if (!nodeIds.has(n.id) && (String(n.label || '').toLowerCase().includes(target) || matching.some(f => f.subject === n.label || f.value === n.label))) {
            nodeIds.add(n.id);
            brief.graph.nodes.push(n);
          }
        });
        (other.graph.edges || []).forEach(e => {
          if (nodeIds.has(e.source) && nodeIds.has(e.target)) {
            const exists = (brief.graph.edges || []).some(x => x.source === e.source && x.target === e.target && x.kind === e.kind);
            if (!exists) brief.graph.edges.push(e);
          }
        });
      }
    } catch {
      // Ignore individual run load errors during multi-hop expansion
    }
  }
  if (addedFacts > 0) {
    message(`Expanded "${selectorValue}" in place: merged ${addedFacts} correlated observation(s) from stored workspace runs.`);
    renderView();
  } else {
    message(`No additional cached observations for "${selectorValue}" in stored runs. Use Pivot to launch a live scan.`);
  }
}

function attachInteractiveSvgPanZoom(svg) {
  if (!svg) return;
  const vbAttr = svg.getAttribute ? svg.getAttribute('viewBox') : svg.attrs?.viewBox;
  if (!vbAttr) return;
  const initial = vbAttr.split(/\s+/).map(Number);
  if (initial.length !== 4 || initial.some(Number.isNaN)) return;
  let [vx, vy, vw, vh] = initial;
  let dragging = false;
  let startX = 0, startY = 0;

  svg.style.cursor = 'grab';
  svg.addEventListener('wheel', e => {
    e.preventDefault();
    const factor = e.deltaY < 0 ? 0.88 : 1.14;
    const newW = Math.max(initial[2] * 0.25, Math.min(initial[2] * 2.5, vw * factor));
    const newH = Math.max(initial[3] * 0.25, Math.min(initial[3] * 2.5, vh * factor));
    vx += (vw - newW) / 2;
    vy += (vh - newH) / 2;
    vw = newW;
    vh = newH;
    svg.setAttribute('viewBox', `${Math.round(vx)} ${Math.round(vy)} ${Math.round(vw)} ${Math.round(vh)}`);
  }, {passive: false});

  svg.addEventListener('mousedown', e => {
    if (e.target?.closest?.('g.graph-node-group, g.geo-pin, g.radial-source-group, g.radial-entity-group')) return;
    dragging = true;
    startX = e.clientX;
    startY = e.clientY;
    svg.style.cursor = 'grabbing';
  });

  svg.addEventListener('mousemove', e => {
    if (!dragging) return;
    const dx = (e.clientX - startX) * (vw / Math.max(300, svg.clientWidth || 800));
    const dy = (e.clientY - startY) * (vh / Math.max(200, svg.clientHeight || 450));
    startX = e.clientX;
    startY = e.clientY;
    vx -= dx;
    vy -= dy;
    svg.setAttribute('viewBox', `${Math.round(vx)} ${Math.round(vy)} ${Math.round(vw)} ${Math.round(vh)}`);
  });

  const stopDrag = () => {
    if (dragging) {
      dragging = false;
      svg.style.cursor = 'grab';
    }
  };
  svg.addEventListener('mouseup', stopDrag);
  svg.addEventListener('mouseleave', stopDrag);
  svg.addEventListener('dblclick', () => {
    [vx, vy, vw, vh] = initial;
    svg.setAttribute('viewBox', initial.join(' '));
  });
}

function showSource(fact) {
  const root = $('#source-content');
  root.replaceChildren(text('h2', fact.attribute));
  const dl = document.createElement('dl');
  for (const [label, value] of Object.entries({
    Subject: fact.subject,
    Observation: fact.value,
    Grade: fact.admiralty,
    Confidence: fact.confidence,
    Flags: (fact.flags || []).join(', ') || 'none',
    Source: fact.source,
    'Evidence class': isRegistration(fact) ? 'Account-registration probe observation' : 'Public-source observation',
    'Collected at': fact.collected_at,
    Mode: fact.collection_mode,
    'Retrieved by': fact.retrieved_by || fact.source,
    'Fact ID': fact.fact_id,
    'Source record': fact.source_record_id,
    'Payload SHA-256': fact.raw_sha256 || '—',
  })) {
    dl.append(text('dt', label), text('dd', value));
  }
  const dd = document.createElement('dd');
  try {
    const url = new URL(fact.source_url);
    if (!['https:', 'http:'].includes(url.protocol)) throw Error();
    const a = text('a', fact.source_url);
    a.href = url.href;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    dd.append(a);
  } catch {
    dd.textContent = fact.source_url || 'No available source URL';
  }
  dl.append(text('dt', 'Source URL'), dd);
  root.append(dl);

  // Source Lineage & Sibling Connection Chart inside the Inspector Drawer
  const lineageBox = text('div', null, 'source-lineage-box');
  lineageBox.append(text('div', 'SOURCE CONNECTION LINEAGE', 'eyebrow'));
  const ns = 'http://www.w3.org/2000/svg';
  const lSvg = document.createElementNS(ns, 'svg');
  lSvg.setAttribute('viewBox', '0 0 460 74');
  const stages = [
    ['SOURCE ADAPTER', String(fact.source || 'osint').slice(0, 18), 10],
    ['SUBJECT', String(fact.subject || '').slice(0, 18), 160],
    ['OBSERVATION', String(fact.value || '').slice(0, 18), 310],
  ];
  stages.forEach(([kindLbl, valLbl, x], idx) => {
    if (idx > 0) {
      const line = document.createElementNS(ns, 'line');
      line.setAttribute('x1', x - 20);
      line.setAttribute('y1', 38);
      line.setAttribute('x2', x);
      line.setAttribute('y2', 38);
      line.setAttribute('class', 'radial-spoke-source');
      lSvg.append(line);
    }
    const r = document.createElementNS(ns, 'rect');
    r.setAttribute('x', x);
    r.setAttribute('y', 14);
    r.setAttribute('width', 130);
    r.setAttribute('height', 46);
    r.setAttribute('rx', 10);
    r.setAttribute('class', idx === 0 ? 'radial-source-node' : idx === 1 ? 'radial-hub-node' : 'radial-entity-node');
    const t1 = document.createElementNS(ns, 'text');
    t1.setAttribute('x', x + 10);
    t1.setAttribute('y', 31);
    t1.setAttribute('class', 'radial-sublabel');
    t1.textContent = kindLbl;
    const t2 = document.createElementNS(ns, 'text');
    t2.setAttribute('x', x + 10);
    t2.setAttribute('y', 48);
    t2.setAttribute('class', 'radial-label');
    t2.textContent = valLbl;
    lSvg.append(r, t1, t2);
  });
  lineageBox.append(lSvg);
  const siblingFacts = (brief?.facts || []).filter(
    f => f.fact_id !== fact.fact_id && (f.source_record_id === fact.source_record_id || f.source === fact.source)
  );
  if (siblingFacts.length) {
    lineageBox.append(text('p', `${siblingFacts.length} additional observation(s) connected to source ${fact.source}:`, 'notice'));
    const sibPills = text('div', null, 'source-connected-pills');
    siblingFacts.slice(0, 8).forEach(sf => {
      const btn = text('button', `${sf.attribute.split('.').pop()}: ${String(sf.value).slice(0, 26)}`, 'source-button');
      btn.type = 'button';
      btn.onclick = () => showSource(sf);
      sibPills.append(btn);
    });
    lineageBox.append(sibPills);
  }
  root.append(lineageBox);

  const actions = text('div', null, 'export-actions source-pivot-bar');
  const isPinned = (snapshot?.operations?.pins || []).some(p => p.fact_id === fact.fact_id);
  const pinBtn = text('button', isPinned ? 'Unpin Finding' : 'Pin Finding to Case', 'secondary');
  pinBtn.type = 'button';
  pinBtn.onclick = () => pinFactToOperations(fact);
  actions.append(pinBtn);

  if (isPivotableValue(fact.value, fact.attribute)) {
    const pivotVal = fact.value.trim();
    const expandBtn = text('button', `Expand in Place`, 'secondary');
    expandBtn.type = 'button';
    expandBtn.onclick = () => expandEntityNodeInPlace(pivotVal);
    const pivotBtn = text('button', `Pivot: Investigate ${pivotVal}`, 'primary');
    pivotBtn.type = 'button';
    pivotBtn.onclick = () => {
      $('#source-dialog').close();
      setWorkspaceView('command');
      if ($('#seed-kind')) $('#seed-kind').value = 'auto';
      $('#domain').value = pivotVal;
      updateSeedInputNotice();
      message(`Loaded selector "${pivotVal}" from source record ${fact.fact_id}. Click Investigate to launch.`);
      $('#domain').focus?.();
    };
    actions.append(expandBtn, pivotBtn);
  }
  root.append(actions);

  syncContextDrawer(`SOURCE RECORD · ${fact.admiralty || 'C3'}`);
  $('#source-dialog').showModal();
}

function empty(title, body) {
  const el = document.createElement('div');
  el.className = 'empty';
  el.append(text('h3', title), text('p', body));
  return el;
}

function table(facts, withFilter = false) {
  if (!facts.length) return empty('No observations in this view.', 'A missing observation is an information gap, not proof of a security issue.');
  const container = document.createElement('div');
  const wrap = document.createElement('div');
  wrap.className = 'panel table-wrap';
  const t = document.createElement('table');
  t.className = 'fact-list';
  const head = document.createElement('thead');
  const tr = document.createElement('tr');
  ['OBSERVATION', 'VALUE', 'SOURCE', 'CONFIDENCE', 'RECORD'].forEach(v => tr.append(text('th', v)));
  head.append(tr);
  t.append(head);
  const body = document.createElement('tbody');

  const renderRows = (subset) => {
    body.replaceChildren();
    subset.forEach(f => {
      const r = document.createElement('tr');
      const a = text('td', f.attribute + ((brief.inferences || []).some(i => i.fact_id === f.fact_id) ? ' · INFERENCE' : ''));
      a.append(text('div', f.subject, 'subject'));
      const valCell = document.createElement('td');
      if (typeof f.value === 'string' && /^https?:\/\//i.test(f.value)) {
        const link = text('a', f.value, 'fact-link');
        link.href = f.value;
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        valCell.append(link);
      } else {
        valCell.textContent = f.value ?? '';
      }
      r.append(a, valCell, text('td', f.source || f.retrieved_by || '—', 'mono muted'), text('td', f.confidence));
      const cell = document.createElement('td');
      cell.append(sourceButton(f));
      r.append(cell);
      body.append(r);
    });
  };
  renderRows(facts);
  t.append(body);
  wrap.append(t);

  if (withFilter && facts.length > 5) {
    const bar = text('div', null, 'filter-bar');
    const input = document.createElement('input');
    input.type = 'text';
    input.className = 'filter-input';
    input.placeholder = `Filter ${facts.length} observations by attribute, value, host, or source…`;
    const countLabel = text('span', `${facts.length} of ${facts.length} shown`, 'mono muted');
    input.oninput = () => {
      const q = input.value.trim().toLowerCase();
      const filtered = !q ? facts : facts.filter(f =>
        (f.attribute || '').toLowerCase().includes(q) ||
        (f.value || '').toLowerCase().includes(q) ||
        (f.subject || '').toLowerCase().includes(q) ||
        (f.source || '').toLowerCase().includes(q)
      );
      countLabel.textContent = `${filtered.length} of ${facts.length} shown`;
      renderRows(filtered);
    };
    bar.append(input, countLabel);
    container.append(bar);
  }
  container.append(wrap);
  return container;
}

function panel(title) {
  const root = document.createElement('section');
  root.className = 'panel';
  const heading = text('div', null, 'panel-title');
  heading.append(text('h2', title));
  const body = text('div', null, 'panel-body');
  root.append(heading, body);
  return {root, body};
}

function gradeClass(letter) {
  if (letter === 'A' || letter === 'B') return 'grade-a';
  if (letter === 'C') return 'grade-c';
  if (letter === 'D' || letter === 'F') return 'grade-f';
  return 'grade-na';
}

function renderPosture(view) {
  const posture = brief.posture;
  if (!posture || !posture.overall) return;
  const overall = posture.overall;
  const banner = text('section', null, 'posture-banner');
  const head = text('div', null, 'posture-head');
  const left = text('div', null, 'posture-overall');
  const badge = text('span', overall.letter || 'N/A', `grade-badge large ${gradeClass(overall.letter)}`);
  const meta = text('div');
  meta.append(
    text('div', 'SECURITY POSTURE GRADE', 'eyebrow'),
    text('h2', overall.score !== null && overall.score !== undefined ? `${overall.score} / 100 Overall Posture Score` : 'Unassessed Posture'),
    text('p', overall.rationale || '', 'notice')
  );
  left.append(badge, meta);
  head.append(left, text('span', `${overall.assessed_domains || 0} / ${overall.total_domains || 5} DOMAINS ASSESSED`, 'tag'));
  banner.append(head);

  const grid = text('div', null, 'posture-grid');
  for (const cat of Object.values(posture.categories || {})) {
    const card = text('div', null, 'posture-card');
    const top = text('div', null, 'posture-card-top');
    top.append(text('h3', cat.label), text('span', cat.letter, `grade-badge ${gradeClass(cat.letter)}`));
    card.append(top, text('p', cat.score !== null ? `Score: ${cat.score}/100` : 'No telemetry', 'mono muted'), text('p', cat.rationale));
    grid.append(card);
  }
  banner.append(grid);
  view.append(banner);

  const exposures = brief.exposures || posture.exposures || [];
  if (exposures.length) {
    const expBox = panel(`Prioritized Security Exposures & Remediation Roadmap (${exposures.length})`);
    exposures.forEach(exp => {
      const item = text('div', null, 'exposure-item');
      const top = text('div', null, 'exposure-top');
      top.append(
        text('span', exp.severity.toUpperCase(), `severity-badge severity-${exp.severity}`),
        text('span', exp.category, 'tag'),
        text('strong', exp.title)
      );
      item.append(top);
      const dl = text('div', null, 'exposure-meta');
      dl.append(
        text('span', 'Observed'), text('div', exp.observed, 'mono'),
        text('span', 'Business Impact'), text('div', exp.consequence),
        text('span', 'Remediation'), text('div', exp.remediation),
        text('span', 'Owner'), text('div', exp.stakeholder_function)
      );
      item.append(dl);
      const citations = text('div', null, 'export-actions exposure-citations');
      (exp.evidence_ids || []).forEach(id => {
        const f = brief.facts.find(x => x.fact_id === id);
        if (f) citations.append(sourceButton(f));
      });
      if (citations.children.length) item.append(citations);
      expBox.body.append(item);
    });
    view.append(expBox.root);
  }
}

function renderView() {
  if (!brief) return;
  const view = $('#view');
  view.replaceChildren();
  const kind = subjectKind();

  if (tab === 'map') { renderGeoMap(view); return; }
  if (tab === 'graph') { renderGraph(view); return; }
  if (tab === 'operations') { renderOperationsTab(view); return; }
  if (tab === 'analysis') { renderAnalysis(view); return; }

  if (tab === 'infrastructure' && isEmailBrief()) {
    view.append(
      text('p', 'Domain, telecom, breach, and network context describes the provider or public mentions, not verified personal infrastructure.', 'notice email-context'),
      table(brief.facts.filter(f => /^(email\.domain|email\.syntax|public\.email\.(syntax|local_part|mailbox_type|provider|deliverable_mx|mx_host|domain_spf|domain_dmarc|checked_services|breach_exposure)|public\.dehashed\.|public\.phone\.|public\.person\.|public\.profile\.|dns|host|whois|intelx|dehashed)\./.test(f.attribute + '.')), true)
    );
    return;
  }
  if (tab === 'infrastructure') {
    view.append(
      text('p', 'DNS, TLS certificates, HTTP headers, Shodan InternetDB ports/CVEs, RIPEstat BGP/ASN routing, RFC 9116 security.txt, RDAP registration, DeHashed/IntelX breach metadata, passive subdomains, and web technology fingerprints.', 'notice'),
      table(brief.facts.filter(f => /^(dns|dnssec|tls|http|ip|bgp|security_txt|host|whois|tech|web|discovery|intelx|dehashed|email\.(dmarc|spf|dkim|mtasts|tlsrpt))\./.test(f.attribute)), true)
    );
    return;
  }
  if (tab === 'evidence') {
    view.append(
      text('p', 'All source-backed observations and labeled inferences. Select any Admiralty grade badge to inspect its underlying record and pivot into discovered selectors.', 'notice'),
      table([...brief.facts, ...(brief.inferences || [])], true)
    );
    return;
  }
  if (tab === 'people' && isEmailBrief()) {
    view.append(text('p', 'Public associations must be linked by the exact selector. A public mention or account-registration observation does not establish real-world identity, employment, or buying authority.', 'notice email-context'));
    const publicFacts = brief.facts.filter(f => !isRegistration(f) && /^(public|email\.public|person|intelx|dehashed)\./.test(f.attribute));
    const registrations = brief.facts.filter(isRegistration);
    view.append(text('h2', kind === 'email' ? 'Public email evidence' : 'Public identity & handle evidence'), table(publicFacts, true));
    if (registrations.length) {
      view.append(
        text('h2', 'Account-registration observations'),
        text('p', 'These observations come from platform registration or profile existence checks. Errors and blocked probes remain unknown.', 'notice'),
        table(registrations, true)
      );
    }
    return;
  }
  if (tab === 'people') {
    const people = new Map();
    brief.facts.filter(f => f.attribute.startsWith('person.')).forEach(f => {
      const key = f.entity_id || f.subject;
      if (!people.has(key)) people.set(key, []);
      people.get(key).push(f);
    });
    const breachFacts = brief.facts.filter(f => f.attribute.startsWith('dehashed.') || f.attribute.startsWith('intelx.'));
    if (breachFacts.length) {
      view.append(
        text('h2', 'DeHashed & Breach Corpus Intelligence'),
        text('p', 'Sanitized breach dataset attributions, credential-exposure counts, and associated corporate selectors indexed by DeHashed / Intelligence X. Cleartext passwords and hashes are stripped in memory.', 'notice'),
        table(breachFacts, true)
      );
    }
    const published = brief.facts.filter(f => f.attribute.startsWith('company.business_') || f.attribute === 'company.contact_page' || f.attribute === 'company.social_url');
    if (published.length) {
      view.append(
        text('h2', 'Published company contacts & social profiles'),
        text('p', 'Business contact details and official social links published on the company website.', 'notice'),
        table(published, true)
      );
    }
    if (!people.size) {
      view.append(empty('No named professional roles observed.', 'Free company-page extraction found no verifiable named staff in the pages it could read. Enable Hunter.io in Settings to enrich organizational contacts.'));
    } else {
      const grid = text('div', null, 'people-grid');
      for (const [, facts] of people) {
        const name = facts[0].subject;
        const card = text('article', null, 'person');
        card.append(text('div', 'BUSINESS CONTACT', 'eyebrow'), text('h3', name));
        facts.forEach(f => {
          card.append(text('p', `${f.attribute.replace('person.', '').replaceAll('_', ' ')} · ${f.value}`), sourceButton(f));
        });
        grid.append(card);
      }
      view.append(grid);
    }
    const roles = brief.power_map || [];
    if (roles.length) {
      const box = panel('Possible professional involvement · inferred');
      roles.forEach(r => {
        const item = text('div', null, 'requirement');
        item.append(text('h3', r.subject + ' · ' + r.possible_involvement.join(' / ')), text('p', r.rationale), text('span', 'LOW CONFIDENCE · TITLE-BASED INFERENCE', 'status warning'));
        box.body.append(item);
      });
      view.append(box.root);
    }
    view.append(text('p', 'Published roles are observations. Possible involvement is an inference; no buying authority or reporting line is established.', 'notice'));
    return;
  }

  // Overview tab
  renderPosture(view);
  if (!isNonCompanyBrief()) {
    renderScores(view);
  } else {
    view.append(text('p', `${kind.charAt(0).toUpperCase() + kind.slice(1)}-focused investigation. Company fit and company security scores do not apply. Public-source associations are observations, not verified identity or ownership.`, 'notice email-context'));
  }

  const grid = text('div', null, 'overview-grid');
  const requirements = panel('Intelligence requirements');
  brief.requirements.forEach(r => {
    const item = text('div', null, 'requirement');
    item.append(text('span', r.status, 'status ' + (r.status === 'answered' ? '' : 'warning')), text('h3', r.question));
    item.append(text('p', r.gap_reason || `${(r.fact_ids || []).length} supporting observations. Review the evidence before drawing conclusions.`));
    requirements.body.append(item);
  });
  if (!brief.requirements.length) requirements.body.append(text('p', 'No requirements were recorded.', 'notice'));
  grid.append(requirements.root);

  const coverage = panel('Collection coverage');
  const sources = [...new Set(brief.facts.map(f => f.source))];
  coverage.body.append(
    text('div', sources.join(' / ') || 'No exportable source records', 'mono'),
    text('p', isEmailBrief() ? 'Collection follows this selector as an independent subject across public OSINT and platform existence sensors.' : 'Parallel collection combines DNS/TLS posture, company pages, RDAP/WHOIS, Shodan InternetDB, certificate transparency, passive DNS, and archives.', 'notice')
  );
  (brief.collection || []).forEach(s => coverage.body.append(text('p', `${s.source} · ${s.outcome} · ${s.facts} observations${s.activity_class ? ' · ' + s.activity_class : ''}`, 'notice')));
  brief.skipped.forEach(s => coverage.body.append(text('p', `${s.adapter}: ${s.reason}`, 'notice warning')));
  coverage.body.append(text('p', 'All assertions pass an accuracy gate. Expired and restricted records are withheld.', 'notice'));
  grid.append(coverage.root);
  view.append(grid);

  const harnessSummary = panel('Agent Harness');
  const analysis = brief.model_analysis;
  harnessSummary.body.append(
    text('span', analysis ? `${analysis.mode.toUpperCase()} · ${analysis.status.toUpperCase()}` : 'DETERMINISTIC · NO MODEL ANALYSIS', 'status'),
    text('p', analysis ? `${analysis.reports?.length || 0} worker outcomes recorded. Conclusions remain cited inferences for human review.` : 'Source collection and evidence rules produced this brief. No model analysis is attached to this investigation.', 'notice')
  );
  const review = text('button', analysis ? 'Review worker rollout' : 'Open Agent Harness', 'secondary');
  review.onclick = () => setTab('analysis');
  harnessSummary.body.append(review);
  view.append(harnessSummary.root);

  if ((brief.inferences || []).length) {
    view.append(text('h2', 'Labeled inferences'));
    view.append(table(brief.inferences));
  }
}

async function openRun(id) {
  selectedRun = id;
  if (workspaceView !== 'command') setWorkspaceView('command');
  $('#landing').hidden = true;
  $('#detail').hidden = false;
  renderRuns();
  $('#view').replaceChildren(text('p', 'Loading source records…', 'loading'));
  try {
    const loaded = await api(`/api/runs/${encodeURIComponent(id)}`);
    if (selectedRun !== id) return;
    brief = loaded;
    const kind = subjectKind();
    $('#company-title').textContent = subjectLabel();
    const kindTitles = {
      email: 'EMAIL INTELLIGENCE',
      username: 'USERNAME INTELLIGENCE',
      ip: 'IP INFRASTRUCTURE INTELLIGENCE',
      phone: 'PHONE INTELLIGENCE',
      person: 'PERSON INTELLIGENCE',
      company: 'COMPANY INTELLIGENCE',
      domain: 'DOMAIN INTELLIGENCE',
    };
    $('#subject-kind').textContent = kindTitles[kind] || 'COMPANY INTELLIGENCE';
    $('[data-tab=people]').textContent = isEmailBrief() ? 'Public associations' : 'People & roles';
    $('[data-tab=infrastructure]').textContent = isEmailBrief() ? 'Domain context' : 'Infrastructure';
    $('#delete-run').disabled = brief.status === 'running';
    $('#run-meta').textContent = `${brief.status.toUpperCase()} / ${brief.run_id.slice(0, 12)} / ${brief.stop_reason}`;

    const metrics = $('#metrics');
    metrics.replaceChildren();
    const hosts = new Set(brief.facts.filter(f => ['dns.subdomain', 'discovery.subdomain', 'host.reverse_dns'].includes(f.attribute)).map(f => f.value)).size;
    const people = new Set(brief.facts.filter(f => f.attribute.startsWith('person.')).map(f => f.subject)).size;
    const postureLetter = brief.posture?.overall?.letter || '—';
    const exposureCount = (brief.exposures || []).length;
    const metricRows = isEmailBrief()
      ? [
          ['PUBLIC OBSERVATIONS', brief.facts.filter(f => /^(public|email\.public)\./.test(f.attribute) && !isRegistration(f)).length, 'Exact-selector public evidence'],
          ['REGISTRATION OBSERVATIONS', brief.facts.some(isRegistration) ? brief.facts.filter(isRegistration).length : '—', brief.facts.some(isRegistration) ? 'Platform endpoint observations' : 'No registration checks in this run'],
          ['OBSERVATIONS', brief.facts.length, 'Total guarded assertions'],
          ['OPEN REQUIREMENTS', brief.requirements.filter(r => r.status !== 'answered').length, 'Unanswered or partial'],
        ]
      : [
          ['POSTURE GRADE', postureLetter, `${exposureCount} prioritized exposure(s)`],
          ['HOSTNAMES & IPS', hosts + new Set(brief.facts.filter(f => f.attribute === 'dns.a').map(f => f.value)).size, 'Discovered hosts & resolved IPs'],
          ['BUSINESS CONTACTS', people, 'Observed professional contacts'],
          ['OBSERVATIONS', brief.facts.length, 'Source-backed assertions'],
        ];
    for (const [label, value, note] of metricRows) {
      const el = text('div', null, 'metric');
      el.append(text('span', label, 'eyebrow'), text('strong', typeof value === 'number' ? String(value).padStart(2, '0') : String(value)), text('small', note));
      metrics.append(el);
    }
    setTab('overview');
    window.scrollTo(0, 0);
  } catch (e) {
    $('#view').replaceChildren(empty('Could not open investigation.', e.message));
  }
}

function goHome() {
  selectedRun = null;
  brief = null;
  $('#landing').hidden = false;
  $('#detail').hidden = true;
  setWorkspaceView('command');
  renderRuns();
  refresh();
}

const RUN_LABELS = {email: 'EML', username: 'USR', ip: 'IP', phone: 'TEL', person: 'PER', company: 'ORG', domain: 'DOM'};

function renderRuns() {
  const list = $('#runs');
  if (!list || !snapshot) return;
  list.replaceChildren();
  const allRuns = snapshot.runs || [];
  const q = runSearchQuery.trim().toLowerCase();
  const filtered = allRuns.filter(r => {
    const label = subjectLabel(r).toLowerCase();
    const kind = r.subject_kind || 'company';
    const kindMatch = runKindFilter === 'all' || (runKindFilter === 'domain' ? ['domain', 'company'].includes(kind) : kind === runKindFilter);
    const textMatch = !q || label.includes(q) || kind.toLowerCase().includes(q) || (r.status || '').toLowerCase().includes(q);
    return kindMatch && textMatch;
  });
  $('#run-count').textContent = (q || runKindFilter !== 'all')
    ? `${filtered.length}/${allRuns.length}`
    : String(allRuns.length).padStart(2, '0');
  if (!allRuns.length) {
    list.append(empty('A clear starting point.', 'Your investigations will appear here. Enter a domain, email, username, or IP above to begin.'));
    return;
  }
  if (!filtered.length) {
    list.append(empty('No matching targets.', 'Clear or adjust the target filter above to view all stored investigations.'));
    return;
  }
  filtered.forEach(r => {
    const item = text('div', null, 'run-item' + (selectedRun === r.id ? ' active-run' : ''));
    const row = text('button', null, 'run-row');
    const label = subjectLabel(r);
    const metaCol = text('span');
    metaCol.append(text('span', label, 'run-name'), text('span', `${date(r.started_at)} · ${(r.status || '').toUpperCase()}`, 'run-date'));
    row.append(
      text('span', RUN_LABELS[r.subject_kind] || 'DOM', 'run-icon'),
      metaCol,
      text('span', 'Open', 'mono muted')
    );
    row.onclick = () => openRun(r.id);
    const remove = text('button', 'Delete', 'danger-button');
    remove.setAttribute('aria-label', 'Delete stored investigation ' + label);
    remove.title = 'Delete stored investigation ' + label;
    remove.disabled = r.status === 'running';
    remove.onclick = () => askDelete(r.id, label);
    item.append(row, remove);
    list.append(item);
  });
}

if ($('#run-filter-input')) {
  $('#run-filter-input').addEventListener('input', e => {
    runSearchQuery = e.target?.value || $('#run-filter-input').value || '';
    renderRuns();
  });
}
if ($('#run-kind-filter')) {
  $('#run-kind-filter').addEventListener('change', e => {
    runKindFilter = e.target?.value || $('#run-kind-filter').value || 'all';
    renderRuns();
  });
}

if ($('#pivot-current-btn')) {
  $('#pivot-current-btn').onclick = () => {
    if (!brief) return;
    const val = subjectLabel();
    $('#domain').value = val;
    if ($('#seed-kind')) $('#seed-kind').value = 'auto';
    updateSeedInputNotice();
    message(`Loaded "${val}" into the Tactical Omnibar. Click Investigate to launch a fresh scan.`);
    $('#domain').focus?.();
  };
}

async function refresh() {
  try {
    snapshot = await api('/api/workspace');
    renderRuns();
    $('#budget').textContent = `${snapshot.budget.period} · $${Number(snapshot.budget.committed).toFixed(2)} / $${Number(snapshot.budget.cap).toFixed(2)} BUDGET`;
    if ($('#host-os-badge') && snapshot.host_os) {
      $('#host-os-badge').textContent = `HOST: ${snapshot.host_os.label.toUpperCase()} (${snapshot.host_os.arch.toUpperCase()})`;
    }
    renderCatalog(snapshot.sources || []);
    renderCloud(snapshot.cloud);
    renderHarness();
    renderRollout(snapshot.job);
    const job = snapshot.job;
    const isJobActive = ['running', 'analyzing'].includes(job.state);
    $('#launch').disabled = isJobActive;
    $('#launch').textContent = isJobActive ? 'Collecting…' : 'Investigate';
    if ($('#live-scan-bar')) {
      $('#live-scan-bar').hidden = !isJobActive;
      if (isJobActive && $('#live-scan-fill')) {
        const pct = job.total ? Math.max(12, Math.min(95, Math.round(((job.completed || 0) / job.total) * 100))) : 25;
        $('#live-scan-fill').style.width = `${pct}%`;
      }
      if ($('#live-sensor-matrix')) {
        const matrix = $('#live-sensor-matrix');
        matrix.replaceChildren();
        if (isJobActive) {
          matrix.append(
            text('span', `ACTIVE SENSOR: ${(job.current_source || 'INITIALIZING').toUpperCase()}`, 'sensor-pill active'),
            text('span', `PROGRESS: ${job.completed || 0} / ${job.total || '…'} ADAPTERS`, 'sensor-pill'),
            text('span', `PHASE: ${(job.phase || job.state || 'COLLECTION').toUpperCase()}`, 'sensor-pill')
          );
        }
      }
    }
    if ($('#chip-mode')) {
      $('#chip-mode').textContent = `MODE: ${harnessMode.toUpperCase()}`;
    }
    if ($('#chip-tools') && Array.isArray(snapshot.sources)) {
      const rdy = snapshot.sources.filter(s => s.ready).length;
      $('#chip-tools').textContent = `SENSORS: ${rdy}/${snapshot.sources.length} READY`;
    }
    if (job.phase === 'analysis' && ['running', 'analyzing'].includes(job.state)) {
      message(`Analyzing cited evidence for ${job.domain || 'subject'} · ${job.analysis_mode || 'selected models'}. Collection has finished.`);
    } else if (['running', 'analyzing'].includes(job.state)) {
      message(`Investigating ${job.seed?.value || job.seed?.normalized || job.domain || 'subject'} · ${job.current_source || 'preparing collection'} · ${job.completed || 0}/${job.total || '…'} sources completed`);
    }
    if (polling && !['running', 'analyzing'].includes(job.state)) {
      polling = false;
      if (job.state === 'complete') {
        message(`Investigation finished for ${job.seed?.value || job.seed?.normalized || job.domain || 'subject'}: ${job.observations || 0} observations, ${job.sources_with_gaps || 0} source gaps.`);
        await openRun(job.run_id);
      } else if (job.state === 'failed') {
        message(job.error, true);
      }
    }
  } catch (e) {
    message(e.message, true);
  }
}

$('#investigate').addEventListener('submit', async e => {
  e.preventDefault();
  $('#launch').disabled = true;
  try {
    validateHarness(harnessMode, harnessProviders);
    const seed = $('#domain').value.trim();
    const chosenKind = $('#seed-kind') ? $('#seed-kind').value : 'auto';
    const isPersonal = seed.includes('@') || ['email', 'username', 'phone', 'person'].includes(chosenKind);
    const result = await api('/api/investigations', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', 'X-Workspace-Token': session},
      body: JSON.stringify({
        seed,
        domain: seed,
        kind: chosenKind || 'auto',
        operator: operatorCallsign,
        contacts: !isPersonal && $('#contacts').checked,
        website: !isPersonal && $('#website').checked,
        analysis_mode: harnessMode,
        providers: harnessMode === 'deterministic' ? [] : harnessProviders,
      }),
    });
    polling = true;
    message(`Starting investigation for ${result.seed?.value || result.seed?.normalized || result.domain || seed}…`);
    await refresh();
  } catch (err) {
    message(err.message, true);
    $('#launch').disabled = false;
  }
});

if ($('#toggle-batch-btn')) {
  $('#toggle-batch-btn').onclick = () => {
    const bp = $('#batch-panel');
    if (bp) bp.hidden = !bp.hidden;
  };
}
if ($('#close-batch-btn')) {
  $('#close-batch-btn').onclick = () => {
    const bp = $('#batch-panel');
    if (bp) bp.hidden = true;
  };
}
if ($('#launch-batch-btn')) {
  $('#launch-batch-btn').onclick = async () => {
    const raw = ($('#batch-targets')?.value || '').trim();
    if (!raw) {
      message('Paste one or more targets (domains, IPs, emails, or usernames) into the batch queue.', true);
      return;
    }
    const caseTitle = ($('#batch-case-title')?.value || '').trim();
    const chosenKind = $('#seed-kind') ? $('#seed-kind').value : 'auto';
    const btn = $('#launch-batch-btn');
    btn.disabled = true;
    btn.textContent = 'Queueing Batch…';
    try {
      const res = await api('/api/investigations/batch', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-Workspace-Token': session},
        body: JSON.stringify({
          targets: raw,
          kind: chosenKind || 'auto',
          case_title: caseTitle,
          operator: operatorCallsign,
          contacts: $('#contacts')?.checked || false,
          website: $('#website')?.checked !== false,
          analysis_mode: harnessMode,
          providers: harnessMode === 'deterministic' ? [] : harnessProviders,
        }),
      });
      if ($('#batch-targets')) $('#batch-targets').value = '';
      if ($('#batch-case-title')) $('#batch-case-title').value = '';
      if ($('#batch-panel')) $('#batch-panel').hidden = true;
      polling = true;
      message(`Launched batch queue for ${res.batch_count || 0} target(s)${res.case?.title ? ` fused into "${res.case.title}"` : ''}.`);
      await refresh();
    } catch (err) {
      message(err.message, true);
    } finally {
      btn.disabled = false;
      btn.textContent = 'Launch Batch Queue';
    }
  };
}

$('#back').onclick = goHome;
$('#home').onclick = goHome;
$('#close-source').onclick = () => $('#source-dialog').close();
document.querySelectorAll('[data-tab]').forEach(b => b.onclick = () => setTab(b.dataset.tab));

$('#export').onclick = () => {
  if (!brief) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(brief, null, 2)], {type: 'application/json'}));
  const a = document.createElement('a');
  a.href = url;
  a.download = `find3r-${brief.run_id}.json`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
};

(async () => {
  try {
    session = (await api('/api/session')).token;
    await refresh();
    polling = ['running', 'analyzing'].includes(snapshot?.job.state);
  } catch (e) {
    message(e.message, true);
  }
})();
setInterval(() => { if (polling) refresh(); }, 1000);

function isLocalOllamaProvider(p) {
  return typeof p === 'string' && (p === 'ollama' || p.startsWith('ollama:'));
}

function validateHarness(mode, providers) {
  if (mode === 'deterministic') return;
  const ready = new Set((snapshot?.runtime_providers || []).filter(p => p.ready).map(p => p.provider));
  const ollamaReady = Boolean(snapshot?.ollama?.installed || snapshot?.ollama?.ready || snapshot?.ollama?.catalog?.length);
  if (providers.some(p => !(ready.has(p) || (ollamaReady && isLocalOllamaProvider(p))))) {
    throw new Error('Choose configured cloud providers or a local Ollama model.');
  }
  if (mode === 'single' && providers.length !== 1) throw new Error('Select one provider for single-model analysis.');
  if (mode === 'multi' && (providers.length < 2 || providers.length > 3)) throw new Error('Select two or three providers for multi-model analysis.');
}

function renderOllama() {
  const ollama = snapshot?.ollama;
  if (!ollama) return;
  if ($('#chip-ollama')) {
    $('#chip-ollama').textContent = `LOCAL AI: ${(ollama.selected_model || 'LLAMA3.1:8B').toUpperCase()}`;
  }
  const badge = $('#ollama-status-badge');
  if (badge) {
    const pulledCount = (ollama.installed_models || []).length;
    badge.textContent = ollama.daemon_running
      ? `OLLAMA ONLINE · ${pulledCount} LOCAL MODEL${pulledCount === 1 ? '' : 'S'}`
      : ollama.installed
      ? 'OLLAMA INSTALLED · READY TO START'
      : 'OLLAMA NOT INSTALLED';
  }
  if ($('#ollama-status-note') && ollama.reason) {
    $('#ollama-status-note').textContent = ollama.reason;
  }
  const select = $('#ollama-model-select');
  const catalog = ollama.catalog || [];
  if (select && catalog.length) {
    select.replaceChildren();
    catalog.forEach(m => {
      const stateTag = m.pulled ? 'PULLED' : 'DOWNLOAD';
      const opt = text('option', `${m.label} (${m.id}) · ${m.size} [${stateTag}] — ${m.specialty}`);
      opt.value = m.id;
      select.append(opt);
    });
    select.value = ollama.selected_model || catalog[0]?.id || 'llama3.1:8b';
  }
  const grid = $('#ollama-providers');
  if (grid) {
    grid.replaceChildren();
    catalog.forEach(m => {
      const pId = `ollama:${m.id}`;
      const label = text('label', null, 'provider-choice');
      const input = document.createElement('input');
      input.type = 'checkbox';
      input.value = pId;
      input.checked = harnessProviders.includes(pId);
      input.disabled = harnessMode === 'deterministic';
      input.setAttribute('aria-label', `Use local Ollama model ${m.id} for analysis`);
      const description = text('span');
      description.append(
        text('strong', `OLLAMA · ${m.label}`),
        text('small', `${m.id} · ${m.size} · $0.00 local`),
        text('small', m.pulled ? `Pulled locally · ${m.specialty}` : `Click Pull Model above · ${m.specialty}`)
      );
      label.append(input, description);
      input.onchange = () => {
        if (harnessMode === 'single') harnessProviders = input.checked ? [pId] : [];
        else harnessProviders = input.checked ? [...harnessProviders, pId] : harnessProviders.filter(n => n !== pId);
        renderHarness();
      };
      grid.append(label);
    });
  }
}

function renderHarness() {
  const providers = snapshot?.runtime_providers || [], ready = providers.filter(p => p.ready);
  const ollamaCatalog = snapshot?.ollama?.catalog || [];
  const totalAvailable = ready.length + ollamaCatalog.length;
  $('#harness-readiness').textContent = `${ready.length} / ${providers.length} PROVIDERS CONFIGURED`;
  const root = $('#harness-providers');
  root.replaceChildren();
  providers.forEach(p => {
    const label = text('label', null, 'provider-choice');
    const input = document.createElement('input');
    input.type = 'checkbox';
    input.value = p.provider;
    input.checked = harnessProviders.includes(p.provider);
    input.disabled = !p.ready || harnessMode === 'deterministic';
    input.setAttribute('aria-label', 'Use ' + p.provider + ' for model analysis');
    const description = text('span');
    description.append(text('strong', p.provider), text('small', p.model || 'No model configured'), text('small', p.ready ? 'Configured · ready for synthesis' : p.reason || 'Not configured'));
    label.append(input, description);
    input.onchange = () => {
      if (harnessMode === 'single') harnessProviders = input.checked ? [p.provider] : [];
      else harnessProviders = input.checked ? [...harnessProviders, p.provider] : harnessProviders.filter(n => n !== p.provider);
      renderHarness();
    };
    root.append(label);
  });
  document.querySelectorAll('input[name=harness-mode]').forEach(input => {
    input.disabled = input.value === 'single' ? !totalAvailable : input.value === 'multi' && totalAvailable < 2;
    input.checked = input.value === harnessMode;
    input.onchange = () => {
      harnessMode = input.value;
      if (harnessMode === 'single' && harnessProviders.length > 1) harnessProviders = harnessProviders.slice(0, 1);
      if (harnessMode === 'single' && !harnessProviders.length && snapshot?.ollama?.selected_model) {
        harnessProviders = [`ollama:${snapshot.ollama.selected_model}`];
      }
      renderHarness();
    };
  });
  renderOllama();
  $('#harness-note').textContent = harnessMode === 'deterministic'
    ? 'Deterministic mode: source collection, A–F security posture grading, and evidence rules. No runtime model calls or model fees.'
    : harnessMode === 'single'
    ? 'Select one local Ollama model ($0 cost) or one configured cloud provider. It receives eligible cited facts after collection.'
    : 'Select two or three local Ollama models or cloud providers. Two specialists analyze separate evidence; a reviewer checks their proposals against the sources.';
}

function renderRollout(job) {
  const root = $('#harness-rollout');
  root.replaceChildren();
  if (!job || job.state === 'idle') return;
  const rollout = text('div', null, 'rollout');
  const running = ['running', 'analyzing'].includes(job.state), analyzing = job.state === 'analyzing' || job.phase === 'analysis';
  const steps = [
    ['Collection', running && !analyzing ? `${job.current_source || 'Preparing sources'} · ${job.completed || 0}/${job.total || '…'}` : analyzing ? 'Source collection finished' : job.state === 'complete' ? 'Finished; review source outcomes' : job.state],
    ['Posture & Evidence Gate', analyzing || job.state === 'complete' ? 'Guarded evidence & A–F posture ready' : 'Applied as observations are processed'],
    ['Analysis', analyzing ? 'Selected model analysis running' : job.state === 'complete' ? 'Open the investigation to review its analysis mode and outcomes' : harnessMode === 'deterministic' ? 'Deterministic · no model calls' : 'Selected models run after collection'],
  ];
  steps.forEach(([name, detail], i) => {
    const item = text('div', null, 'rollout-step' + (running && ((i === 0 && !analyzing) || (i === 2 && analyzing)) ? ' running' : ''));
    item.append(text('strong', name), text('p', detail));
    rollout.append(item);
  });
  root.append(rollout);
}

function askDelete(id, label) {
  deleteTarget = {id, label};
  $('#delete-title').textContent = label;
  $('#delete-message').textContent = '';
  $('#delete-dialog').showModal();
}
$('#delete-run').onclick = () => { if (brief) askDelete(brief.run_id, subjectLabel()); };
$('#close-delete').onclick = () => $('#delete-dialog').close();
$('#cancel-delete').onclick = () => $('#delete-dialog').close();
$('#confirm-delete').onclick = async () => {
  if (!deleteTarget) return;
  const target = deleteTarget;
  $('#confirm-delete').disabled = true;
  try {
    const result = await api(`/api/runs/${encodeURIComponent(target.id)}`, {method: 'DELETE', headers: {'X-Workspace-Token': session}});
    $('#delete-dialog').close();
    deleteTarget = null;
    if (selectedRun === target.id) goHome();
    else await refresh();
    const incomplete = result.report_cleanup_failures?.length || result.journal_checkpointed === false;
    message(incomplete ? 'Investigation records deleted; some report files or database journal cleanup could not finish. Check local storage permissions.' : `Deleted stored investigation for ${target.label}.`, Boolean(incomplete));
  } catch (error) {
    $('#delete-message').textContent = error.message;
  } finally {
    $('#confirm-delete').disabled = false;
  }
};

$('#harness-nav').onclick = () => {
  if (brief) setTab('analysis');
  else setWorkspaceView('harness');
};
if ($('#cloud-nav')) {
  $('#cloud-nav').onclick = () => setWorkspaceView('cloud');
}
if ($('#tools-nav')) {
  $('#tools-nav').onclick = () => setWorkspaceView('tools');
}
['command', 'cloud', 'harness', 'tools'].forEach(k => {
  const btn = $(`#ws-tab-${k}`);
  if (btn) btn.onclick = () => setWorkspaceView(k);
});
if ($('#chip-route')) $('#chip-route').onclick = () => setWorkspaceView('cloud');
if ($('#chip-mode')) $('#chip-mode').onclick = () => setWorkspaceView('harness');
if ($('#chip-tools')) $('#chip-tools').onclick = () => setWorkspaceView('tools');
if ($('#dock-open-cloud')) $('#dock-open-cloud').onclick = () => setWorkspaceView('cloud');
if ($('#cloud-key-btn')) $('#cloud-key-btn').onclick = openSettings;

function renderCloud(cloud) {
  const root = $('#cloud-nodes');
  if (!root || !cloud) return;
  root.replaceChildren();

  const regionSelect = $('#vps-region');
  if (regionSelect && regionSelect.options.length <= 1 && Array.isArray(cloud.regions)) {
    cloud.regions.forEach(r => {
      const opt = text('option', `${r.city} (${r.country}) · ${r.id.toUpperCase()}`);
      opt.value = r.id;
      regionSelect.append(opt);
    });
  }

  const activeId = cloud.active_node_id || 'local';
  const nodes = cloud.nodes || [];
  const activeNode = nodes.find(n => n.id === activeId);

  if ($('#cloud-active-badge')) {
    $('#cloud-active-badge').textContent = activeNode
      ? `ROUTE: VULTR VPS · ${activeNode.ip || 'ASSIGNING IP'} (${activeNode.region_name})`
      : 'ROUTE: LOCAL MACHINE';
  }
  if ($('#rail-node-label')) {
    $('#rail-node-label').textContent = activeNode ? 'VPS' : 'LOCAL';
  }
  if ($('#header-node-status')) {
    $('#header-node-status').textContent = activeNode
      ? `VULTR VPS (${activeNode.ip || activeNode.region.toUpperCase()})`
      : 'LOCAL WORKSPACE';
  }
  if ($('#chip-route')) {
    $('#chip-route').textContent = activeNode
      ? `ROUTE: VPS (${activeNode.ip || activeNode.region.toUpperCase()})`
      : 'ROUTE: LOCAL';
  }
  if ($('#dock-proxy-badge')) {
    $('#dock-proxy-badge').textContent = activeNode
      ? `VPS · ${activeNode.ip || activeNode.region.toUpperCase()}`
      : 'LOCAL';
  }
  if ($('#dock-proxy-status')) {
    $('#dock-proxy-status').textContent = activeNode
      ? `Routing all OSINT scans via Ubuntu 24.04 VPS ${activeNode.ip || activeNode.label} (${activeNode.region_name}).`
      : 'Direct local execution. Spin up an ephemeral Ubuntu 24.04 VPS on Vultr to route OSINT scans through a disposable IP.';
  }

  // 1. Local Machine card
  const localCard = text('div', null, 'cloud-node-card' + (activeId === 'local' ? ' active-node' : ''));
  const localTop = text('div');
  localTop.append(
    text('div', 'DIRECT EXECUTION', 'eyebrow'),
    text('h3', 'Local Machine (This Host)'),
    text('p', activeId === 'local' ? 'ACTIVE RUNNER' : 'STANDBY', 'status ' + (activeId === 'local' ? '' : 'warning')),
    text('p', 'Runs OSINT adapters and installed CLI binaries directly from this machine.', 'notice')
  );
  const localBtn = text('button', activeId === 'local' ? 'Active Execution Route' : 'Use Local Machine', 'secondary');
  localBtn.type = 'button';
  localBtn.disabled = activeId === 'local';
  localBtn.onclick = async () => {
    try {
      const updated = await api('/api/cloud/select', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-Workspace-Token': session},
        body: JSON.stringify({node_id: 'local'}),
      });
      renderCloud(updated);
      message('Switched execution route to Local Machine.');
    } catch (e) {
      message(e.message, true);
    }
  };
  localCard.append(localTop, localBtn);
  root.append(localCard);

  // 2. Ephemeral Vultr Ubuntu VPS cards
  nodes.forEach(n => {
    const isSelected = activeId === n.id;
    const card = text('div', null, 'cloud-node-card' + (isSelected ? ' active-node' : ''));
    const top = text('div');
    const readyState = n.status === 'active' && n.ip;
    top.append(
      text('div', `VULTR UBUNTU 24.04 · ${n.region_name.toUpperCase()}`, 'eyebrow'),
      text('h3', `${n.ip || 'Assigning IPv4…'} · ${n.label}`),
      text('p', `${n.status.toUpperCase()} · ${n.server_status || n.power_status}${isSelected ? ' · ACTIVE RUNNER' : ''}`, 'status ' + (readyState ? '' : 'warning')),
      text('div', n.ssh_command || '', 'cloud-ssh-box')
    );
    const actions = text('div', null, 'export-actions');
    const selectBtn = text('button', isSelected ? 'Active VPS Route' : 'Route Scans via VPS', 'secondary');
    selectBtn.type = 'button';
    selectBtn.disabled = isSelected;
    selectBtn.onclick = async () => {
      try {
        const updated = await api('/api/cloud/select', {
          method: 'POST',
          headers: {'Content-Type': 'application/json', 'X-Workspace-Token': session},
          body: JSON.stringify({node_id: n.id}),
        });
        renderCloud(updated);
        message(`Routing investigations through Ubuntu VPS ${n.ip || n.label} (${n.region_name}).`);
      } catch (e) {
        message(e.message, true);
      }
    };
    const copyBtn = text('button', 'Copy SSH', 'secondary');
    copyBtn.type = 'button';
    copyBtn.disabled = !n.ssh_command;
    copyBtn.onclick = async () => {
      try {
        if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
          await navigator.clipboard.writeText(n.ssh_command);
        }
        copyBtn.textContent = 'Copied SSH';
        message(`Copied SSH command for ${n.ip || n.label} to clipboard.`);
        setTimeout(() => { copyBtn.textContent = 'Copy SSH'; }, 1800);
      } catch {
        message(`SSH Command: ${n.ssh_command}`);
      }
    };
    const destroyBtn = text('button', 'Destroy VPS', 'danger-button');
    destroyBtn.type = 'button';
    destroyBtn.onclick = async () => {
      destroyBtn.disabled = true;
      destroyBtn.textContent = 'Destroying…';
      try {
        const res = await api('/api/cloud/destroy', {
          method: 'POST',
          headers: {'Content-Type': 'application/json', 'X-Workspace-Token': session},
          body: JSON.stringify({instance_id: n.id}),
        });
        if (res.cloud) renderCloud(res.cloud);
        message(`Destroyed Vultr Ubuntu VPS ${n.ip || n.label}.`);
      } catch (e) {
        message(e.message, true);
        destroyBtn.disabled = false;
        destroyBtn.textContent = 'Destroy VPS';
      }
    };
    actions.append(selectBtn, copyBtn, destroyBtn);
    card.append(top, actions);
    root.append(card);
  });
}

if ($('#spinup-vps-btn')) {
  $('#spinup-vps-btn').onclick = async () => {
    const btn = $('#spinup-vps-btn');
    const region = $('#vps-region') ? $('#vps-region').value : 'random';
    btn.disabled = true;
    btn.textContent = 'Provisioning Ubuntu VPS…';
    try {
      const res = await api('/api/cloud/spinup', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-Workspace-Token': session},
        body: JSON.stringify({region, auto_select: true}),
      });
      if (res.cloud) renderCloud(res.cloud);
      const created = res.created || {};
      message(`Spun up ephemeral Ubuntu 24.04 VPS (${created.label}) in ${created.region_name}. Cloud-init is installing OSINT tools.`);
    } catch (e) {
      message(e.message, true);
    } finally {
      btn.disabled = false;
      btn.textContent = 'Spin Up Random Ubuntu VPS';
    }
  };
}

if ($('#rotate-vps-btn')) {
  $('#rotate-vps-btn').onclick = async () => {
    const btn = $('#rotate-vps-btn');
    const region = $('#vps-region') ? $('#vps-region').value : 'random';
    btn.disabled = true;
    btn.textContent = 'Rotating VPS IP…';
    try {
      const cloud = await api('/api/cloud/rotate', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-Workspace-Token': session},
        body: JSON.stringify({region}),
      });
      renderCloud(cloud);
      message('Rotated to a new ephemeral Vultr Ubuntu VPS and destroyed previous instance(s).');
    } catch (e) {
      message(e.message, true);
    } finally {
      btn.disabled = false;
      btn.textContent = 'Rotate VPS IP';
    }
  };
}

if ($('#sync-vps-btn')) {
  $('#sync-vps-btn').onclick = async () => {
    const btn = $('#sync-vps-btn');
    btn.disabled = true;
    btn.textContent = 'Syncing…';
    try {
      const cloud = await api('/api/cloud/sync', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-Workspace-Token': session},
        body: JSON.stringify({}),
      });
      renderCloud(cloud);
      message(`Synced ${cloud.nodes?.length || 0} Vultr ephemeral instance(s).`);
    } catch (e) {
      message(e.message, true);
    } finally {
      btn.disabled = false;
      btn.textContent = 'Sync Nodes';
    }
  };
}

function updateSeedInputNotice() {
  const val = $('#domain').value.trim();
  const kind = $('#seed-kind') ? $('#seed-kind').value : 'auto';
  const isPersonal = val.includes('@') || ['email', 'username', 'phone', 'person'].includes(kind);
  $('#seed-notice').hidden = !isPersonal;
  $('#website').disabled = isPersonal;
  if ($('#kind-pills')) {
    $('#kind-pills').querySelectorAll('.kind-pill').forEach(b => {
      b.classList.toggle('active', b.dataset?.kindVal === kind || b.attrs?.['data-kind-val'] === kind);
    });
  }
}
$('#domain').addEventListener('input', updateSeedInputNotice);
if ($('#seed-kind')) $('#seed-kind').addEventListener('change', updateSeedInputNotice);
if ($('#kind-pills')) {
  $('#kind-pills').addEventListener('click', e => {
    const btn = e.target;
    const kVal = btn?.dataset?.kindVal || btn?.attrs?.['data-kind-val'];
    if (kVal && $('#seed-kind')) {
      $('#seed-kind').value = kVal;
      updateSeedInputNotice();
      $('#domain').focus?.();
    }
  });
}

// Operator Session & Team Access Dialog
function openOperatorDialog() {
  const dlg = $('#operator-dialog');
  if (!dlg) return;
  if ($('#operator-message')) $('#operator-message').textContent = '';
  const team = snapshot?.team || {};
  if ($('#operator-session-state')) {
    const modeTag = team.team_mode ? 'SHARED PARTNER MODE' : 'LOCAL LOOPBACK';
    $('#operator-session-state').textContent = session ? `ACTIVE · ${modeTag}` : 'LOCAL SESSION';
  }
  if ($('#operator-node-state')) {
    const opsCount = (team.operators || []).length;
    $('#operator-node-state').textContent = opsCount
      ? `${opsCount} OPERATOR${opsCount === 1 ? '' : 'S'} ACTIVE`
      : ($('#header-node-status') ? $('#header-node-status').textContent : 'LOCAL WORKSPACE');
  }
  if ($('#operator-team-list')) {
    const opsList = (team.operators || []).map(o => `${o.callsign} (${o.role || 'analyst'})`);
    $('#operator-team-list').textContent = opsList.length
      ? `Online: ${opsList.join(' · ')}`
      : 'Solo session · register callsign below to broadcast presence to partner.';
  }
  if ($('#operator-callsign')) {
    $('#operator-callsign').value = operatorCallsign;
  }
  if ($('#operator-team-key')) {
    $('#operator-team-key').value = teamPasskey;
  }
  dlg.showModal();
}
if ($('#operator-login-btn')) $('#operator-login-btn').onclick = openOperatorDialog;
if ($('#close-operator')) $('#close-operator').onclick = () => $('#operator-dialog').close();
if ($('#cancel-operator')) $('#cancel-operator').onclick = () => $('#operator-dialog').close();
if ($('#operator-open-cloud')) {
  $('#operator-open-cloud').onclick = () => {
    $('#operator-dialog').close();
    setWorkspaceView('cloud');
  };
}
if ($('#operator-form')) {
  $('#operator-form').addEventListener('submit', async e => {
    e.preventDefault();
    const val = ($('#operator-callsign')?.value || '').trim() || 'local-analyst';
    const keyVal = ($('#operator-team-key')?.value || '').trim();
    operatorCallsign = val;
    if (keyVal) teamPasskey = keyVal;
    try {
      const res = await api('/api/operator/auth', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-Workspace-Token': session},
        body: JSON.stringify({callsign: val, team_key: teamPasskey}),
      });
      if (snapshot && res) {
        snapshot.team = {
          ...(snapshot.team || {}),
          team_mode: res.team_mode,
          operators: res.operators || [],
        };
      }
      const opsCount = (res?.operators || []).length || 1;
      if ($('#operator-login-btn')) {
        $('#operator-login-btn').textContent = `OPERATOR: ${val.toUpperCase()} · ${opsCount} ONLINE`;
      }
      $('#operator-dialog').close();
      message(`Synced operator session as "${val}" (${opsCount} active operator${opsCount === 1 ? '' : 's'}).`);
    } catch (err) {
      if ($('#operator-message')) $('#operator-message').textContent = err.message;
      else message(err.message, true);
    }
  });
}

// Settings dialog logic
async function openSettings() {
  const dlg = $('#settings-dialog');
  if (!dlg) return;
  $('#settings-message').textContent = '';
  try {
    const s = await api('/api/settings');
    Object.entries(s.keys || {}).forEach(([k, info]) => {
      const el = $(`#status-${k}`);
      if (el) el.textContent = info.configured ? `Configured (${info.masked})` : 'not set';
      const inp = document.querySelector(`input[data-key="${k}"]`);
      if (inp) inp.value = '';
    });
    Object.entries(s.models || {}).forEach(([p, m]) => {
      const inp = document.querySelector(`input[data-model="${p}"]`);
      if (inp) inp.value = m || '';
    });
    if ($('#setting-budget') && s.monthly_budget_usd) {
      $('#setting-budget').value = Number(s.monthly_budget_usd);
    }
  } catch (e) {
    $('#settings-message').textContent = e.message;
  }
  dlg.showModal();
}
if ($('#open-settings')) $('#open-settings').onclick = openSettings;
if ($('#settings-nav')) $('#settings-nav').onclick = openSettings;
if ($('#config-keys-btn')) $('#config-keys-btn').onclick = openSettings;
if ($('#close-settings')) $('#close-settings').onclick = () => $('#settings-dialog').close();
if ($('#cancel-settings')) $('#cancel-settings').onclick = () => $('#settings-dialog').close();

if ($('#load-default-profile')) {
  $('#load-default-profile').onclick = async () => {
    try {
      const defaultProfile = {
        name: 'Managed Security & Infrastructure Services',
        services: ['Email Security & DMARC Enforcement', 'Attack Surface Management', 'Web Application Hardening'],
        criteria: [
          {id: 'dmarc-weak', label: 'Unenforced DMARC (none/absent)', service: 'Email Security & DMARC Enforcement', attribute: 'email.dmarc.policy', contains: 'none', weight: 4},
          {id: 'spf-soft', label: 'Softfail SPF (~all)', service: 'Email Security & DMARC Enforcement', attribute: 'email.spf.qualifier', equals: '~all', weight: 2},
          {id: 'dnssec-unsigned', label: 'Unsigned DNSSEC zone', service: 'Attack Surface Management', attribute: 'dnssec.status', equals: 'absent', weight: 2},
          {id: 'web-assessed', label: 'Active public web footprint', service: 'Web Application Hardening', attribute: 'http.security_assessed', equals: 'true', weight: 2},
        ],
      };
      await api('/api/profile', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-Workspace-Token': session},
        body: JSON.stringify(defaultProfile),
      });
      $('#settings-message').textContent = 'Loaded default Managed Security & Infrastructure Services fit profile.';
      await refresh();
    } catch (e) {
      $('#settings-message').textContent = e.message;
    }
  };
}

if ($('#settings-form')) {
  $('#settings-form').addEventListener('submit', async e => {
    e.preventDefault();
    const keys = {}, models = {};
    document.querySelectorAll('input[data-key]').forEach(inp => {
      if (inp.value.trim()) keys[inp.dataset.key] = inp.value.trim();
    });
    document.querySelectorAll('input[data-model]').forEach(inp => {
      if (inp.value.trim()) models[inp.dataset.model] = inp.value.trim();
    });
    const budget = $('#setting-budget') ? $('#setting-budget').value : '100';
    try {
      await api('/api/settings', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-Workspace-Token': session},
        body: JSON.stringify({keys, models, monthly_budget_usd: budget}),
      });
      $('#settings-dialog').close();
      message('Workspace configuration, API keys, and budget updated.');
      await refresh();
    } catch (err) {
      $('#settings-message').textContent = err.message;
    }
  });
}

async function triggerToolInstall(toolName, btn) {
  const statusEl = $('#tool-install-status');
  const origText = btn ? btn.textContent : '';
  if (btn) {
    btn.disabled = true;
    btn.textContent = toolName === 'all' ? 'Installing missing tools…' : `Installing ${toolName}…`;
  }
  if (statusEl) statusEl.textContent = `Running installer for ${toolName}…`;
  try {
    const res = await api('/api/tools/install', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', 'X-Workspace-Token': session},
      body: JSON.stringify({tool: toolName}),
    });
    if (res.sources) renderCatalog(res.sources);
    if (toolName === 'all') {
      const msg = `Auto-install finished: ${res.installed_count || 0}/${res.total || 0} CLI tools installed and ready.`;
      if (statusEl) statusEl.textContent = msg;
      message(msg);
    } else {
      const msg = res.message || `${toolName}: ${res.status}`;
      if (statusEl) statusEl.textContent = msg;
      message(msg, !res.installed);
    }
    await refresh();
  } catch (err) {
    if (statusEl) statusEl.textContent = err.message;
    message(err.message, true);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = origText;
    }
  }
}

if ($('#refresh-tools-btn')) {
  $('#refresh-tools-btn').onclick = async () => {
    const statusEl = $('#tool-install-status');
    if (statusEl) statusEl.textContent = 'Scanning installed binaries…';
    try {
      const res = await api('/api/tools/refresh', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-Workspace-Token': session},
        body: JSON.stringify({}),
      });
      if (res.sources) renderCatalog(res.sources);
      if (statusEl) statusEl.textContent = `Verified ${res.ready_count} ready sources & CLI tools.`;
    } catch (err) {
      if (statusEl) statusEl.textContent = err.message;
    }
  };
}

if ($('#autoinstall-tools-btn')) {
  $('#autoinstall-tools-btn').onclick = () => triggerToolInstall('all', $('#autoinstall-tools-btn'));
}

async function downloadPreinstallScript(targetOs) {
  try {
    const data = await api(`/api/tools/preinstall/${encodeURIComponent(targetOs)}`);
    const url = URL.createObjectURL(new Blob([data.script], {type: data.content_type || 'text/plain;charset=utf-8'}));
    const a = document.createElement('a');
    a.href = url;
    a.download = data.filename || `find3r-preinstall-${targetOs}.sh`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    message(`Downloaded ${data.filename} pre-installer package script.`);
  } catch (err) {
    message(err.message, true);
  }
}

if ($('#dl-win-installer')) $('#dl-win-installer').onclick = () => downloadPreinstallScript('windows');
if ($('#dl-linux-installer')) $('#dl-linux-installer').onclick = () => downloadPreinstallScript('linux');
if ($('#dl-mac-installer')) $('#dl-mac-installer').onclick = () => downloadPreinstallScript('macos');

if ($('#chip-ollama')) $('#chip-ollama').onclick = () => setWorkspaceView('harness');

function chosenOllamaModel() {
  const custom = ($('#ollama-custom-model')?.value || '').trim();
  if (custom) return custom;
  return $('#ollama-model-select') ? $('#ollama-model-select').value : 'llama3.1:8b';
}

if ($('#ollama-create-btn')) {
  $('#ollama-create-btn').onclick = async () => {
    const btn = $('#ollama-create-btn');
    const name = ($('#ollama-import-name')?.value || '').trim();
    const source = ($('#ollama-import-source')?.value || '').trim();
    if (!name || !source) {
      message('Enter both a new model name (e.g. my-osint:latest) and a local .gguf/Modelfile path or base tag.', true);
      return;
    }
    btn.disabled = true;
    btn.textContent = 'Importing…';
    if ($('#ollama-status-note')) {
      $('#ollama-status-note').textContent = `Building and registering local model ${name} from ${source}…`;
    }
    try {
      const updated = await api('/api/ollama/create', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-Workspace-Token': session},
        body: JSON.stringify({name, source}),
      });
      if ($('#ollama-import-name')) $('#ollama-import-name').value = '';
      if ($('#ollama-import-source')) $('#ollama-import-source').value = '';
      if (snapshot) snapshot.ollama = updated;
      if (harnessMode === 'deterministic') harnessMode = 'single';
      harnessProviders = [`ollama:${updated.selected_model || name}`];
      renderHarness();
      if ($('#chip-mode')) $('#chip-mode').textContent = `MODE: ${harnessMode.toUpperCase()}`;
      message(updated.message || `Imported local model ${updated.selected_model || name} ($0 cost).`);
    } catch (err) {
      message(err.message, true);
      if ($('#ollama-status-note')) $('#ollama-status-note').textContent = err.message;
    } finally {
      btn.disabled = false;
      btn.textContent = 'Import / Build Model';
    }
  };
}

if ($('#ollama-select-btn')) {
  $('#ollama-select-btn').onclick = async () => {
    const model = chosenOllamaModel();
    try {
      const updated = await api('/api/ollama/select', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-Workspace-Token': session},
        body: JSON.stringify({model}),
      });
      if ($('#ollama-custom-model')) $('#ollama-custom-model').value = '';
      if (snapshot) snapshot.ollama = updated;
      if (harnessMode === 'deterministic') harnessMode = 'single';
      harnessProviders = [`ollama:${updated.selected_model || model}`];
      renderHarness();
      if ($('#chip-mode')) $('#chip-mode').textContent = `MODE: ${harnessMode.toUpperCase()}`;
      message(`Selected local Ollama model ${updated.selected_model || model} for Agent Harness synthesis ($0 cost).`);
    } catch (err) {
      message(err.message, true);
    }
  };
}

if ($('#ollama-pull-btn')) {
  $('#ollama-pull-btn').onclick = async () => {
    const btn = $('#ollama-pull-btn');
    const model = chosenOllamaModel();
    btn.disabled = true;
    btn.textContent = `Pulling ${model}…`;
    if ($('#ollama-status-note')) {
      $('#ollama-status-note').textContent = `Downloading ${model} into local Ollama runtime (this may take a few minutes on first pull)…`;
    }
    try {
      const updated = await api('/api/ollama/pull', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-Workspace-Token': session},
        body: JSON.stringify({model}),
      });
      if ($('#ollama-custom-model')) $('#ollama-custom-model').value = '';
      if (snapshot) snapshot.ollama = updated;
      if (harnessMode === 'deterministic') harnessMode = 'single';
      harnessProviders = [`ollama:${updated.selected_model || model}`];
      renderHarness();
      message(`Pulled local Ollama model ${updated.selected_model || model}. Ready for offline $0 synthesis.`);
    } catch (err) {
      message(err.message, true);
      if ($('#ollama-status-note')) $('#ollama-status-note').textContent = err.message;
    } finally {
      btn.disabled = false;
      btn.textContent = 'Pull / Download Model';
    }
  };
}

if ($('#ollama-refresh-btn')) {
  $('#ollama-refresh-btn').onclick = async () => {
    const btn = $('#ollama-refresh-btn');
    btn.disabled = true;
    btn.textContent = 'Scanning…';
    try {
      const updated = await api('/api/ollama/status');
      if (snapshot) snapshot.ollama = updated;
      renderHarness();
      const count = (updated.installed_models || []).length;
      message(`Detected ${count} locally installed Ollama model(s).`);
    } catch (err) {
      message(err.message, true);
    } finally {
      btn.disabled = false;
      btn.textContent = 'Refresh Local Models';
    }
  };
}

if ($('#ollama-install-btn')) {
  $('#ollama-install-btn').onclick = async () => {
    const btn = $('#ollama-install-btn');
    btn.disabled = true;
    btn.textContent = 'Installing Ollama…';
    try {
      const updated = await api('/api/ollama/install', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-Workspace-Token': session},
        body: JSON.stringify({}),
      });
      if (snapshot) snapshot.ollama = updated;
      renderHarness();
      message(updated.reason || 'Ollama runtime installed and started.');
    } catch (err) {
      message(err.message, true);
    } finally {
      btn.disabled = false;
      btn.textContent = 'Install / Start Ollama';
    }
  };
}

function renderCatalog(sources) {
  const root = $('#source-catalog');
  root.replaceChildren();
  const available = sources.filter(s => s.ready).length;
  $('#source-count').textContent = `${available} / ${sources.length} SOURCES READY`;
  sources.forEach(s => {
    const card = text('div', null, 'source-card');
    const registration = /holehe|ghunt|sherlock|maigret|socialscan|email-osint|username-osint|registration|recovery/i.test(s.name);
    const category = registration ? 'ACCOUNT / HANDLE ENUMERATION' : s.mode === 'third_party_passive' ? 'PASSIVE OSINT / TELEMETRY' : s.mode === 'direct_contact' ? 'DIRECT TLS / HTTP / DNS INSPECTION' : 'ACTIVE COLLECTION';
    const stateLabel = s.ready && s.binary_path ? 'available · installed' : s.state;
    card.append(text('h3', `${s.name} · Tier ${s.tier}`), text('div', category, 'source-category'), text('p', stateLabel, 'status ' + (s.ready ? '' : 'warning')), text('p', s.description, 'notice'));
    if (s.ready && s.binary_path) {
      card.append(text('span', `Binary: ${s.binary_path}`, 'tool-bin-path'));
    }
    if (!s.ready && s.reason) card.append(text('p', s.reason, 'notice'));
    if (!s.ready && s.installable) {
      const btn = text('button', `Install ${s.name}`, 'secondary tool-install-btn');
      btn.type = 'button';
      btn.onclick = () => triggerToolInstall(s.name, btn);
      card.append(btn);
    }
    root.append(card);
  });
}

function renderScores(view) {
  if (!brief.scores) return;
  const grid = text('div', null, 'score-grid');
  for (const [key, label] of [['commercial_fit', 'Commercial fit'], ['security_needs', 'Evidence of potential security needs']]) {
    const score = brief.scores[key];
    if (!score) continue;
    const box = panel(label);
    box.body.append(
      text('strong', score.score === null ? '—' : String(score.score), 'score-value'),
      text('span', score.score === null ? 'UNASSESSED' : ' / 100', 'eyebrow'),
      text('p', `${score.coverage}% weighted criterion coverage · ${score.assessed_count}/${score.criteria_count} assessed`, 'mono muted'),
      text('p', score.explanation, 'notice')
    );
    const details = document.createElement('details');
    details.append(text('summary', 'Weights, evidence & unknowns'));
    (score.criteria || []).forEach(c => {
      const row = text('div', null, 'requirement');
      row.append(text('h3', `${c.label} · weight ${c.weight} · ${c.status}`), text('p', c.explanation));
      if (c.contribution !== null) row.append(text('p', `Score contribution: ${c.contribution}`, 'mono muted'));
      (c.evidence_ids || []).forEach(id => {
        const f = brief.facts.find(x => x.fact_id === id);
        if (f) row.append(sourceButton(f));
      });
      details.append(row);
    });
    box.body.append(details);
    grid.append(box.root);
  }
  view.append(grid);
}

function findShortestEntityPath(nodes, edges, fromId, toId) {
  if (!fromId || !toId || fromId === toId) return null;
  const adj = new Map();
  nodes.forEach(n => adj.set(n.id, []));
  edges.forEach((e, idx) => {
    if (!adj.has(e.source)) adj.set(e.source, []);
    if (!adj.has(e.target)) adj.set(e.target, []);
    adj.get(e.source).push({neighbor: e.target, edgeIdx: idx});
    adj.get(e.target).push({neighbor: e.source, edgeIdx: idx});
  });
  const queue = [[fromId]];
  const visited = new Set([fromId]);
  const edgeTrail = new Map();
  while (queue.length) {
    const path = queue.shift();
    const curr = path[path.length - 1];
    if (curr === toId) {
      const edgeIndices = new Set();
      for (let i = 1; i < path.length; i++) {
        const key = `${path[i - 1]}->${path[i]}`;
        if (edgeTrail.has(key)) edgeIndices.add(edgeTrail.get(key));
      }
      return {nodeIds: new Set(path), orderedIds: path, edgeIndices};
    }
    for (const {neighbor, edgeIdx} of (adj.get(curr) || [])) {
      if (!visited.has(neighbor)) {
        visited.add(neighbor);
        edgeTrail.set(`${curr}->${neighbor}`, edgeIdx);
        queue.push([...path, neighbor]);
      }
    }
  }
  return null;
}

let graphPathFrom = '', graphPathTo = '', activePathResult = null;

function renderGraph(view) {
  const graph = brief.graph;
  if (!graph) {
    view.append(empty('No graph available.', 'Reopen a completed investigation to build its evidence graph.'));
    return;
  }
  view.append(text('p', graph.identity_policy + ' ' + graph.context, 'notice'));
  const categories = ['organization', 'domain', 'person', 'email', 'username', 'account', 'phone', 'ip', 'url', 'observation'];
  const all = graph.nodes || [];
  const presentKinds = categories.filter(k => all.some(n => n.kind === k));

  const toolbar = text('div', null, 'graph-toolbar');
  const pills = text('div', null, 'graph-pills');
  ['all', ...presentKinds].forEach(k => {
    const b = text('button', k.toUpperCase(), 'graph-pill' + (graphKindFilter === k ? ' active' : ''));
    b.onclick = () => { graphKindFilter = k; renderView(); };
    pills.append(b);
  });
  const zoomBox = text('div', null, 'export-actions');
  const zOut = text('button', 'Zoom Out', 'secondary');
  const zReset = text('button', `${Math.round(graphZoom * 100)}%`, 'secondary');
  const zIn = text('button', 'Zoom In', 'secondary');
  zOut.onclick = () => { graphZoom = Math.max(0.5, +(graphZoom - 0.2).toFixed(1)); renderView(); };
  zReset.onclick = () => { graphZoom = 1; renderView(); };
  zIn.onclick = () => { graphZoom = Math.min(2.0, +(graphZoom + 0.2).toFixed(1)); renderView(); };
  zoomBox.append(zOut, zReset, zIn);
  toolbar.append(pills, zoomBox);
  view.append(toolbar);

  // Shortest-Path Link Finder Bar
  if (all.length >= 2) {
    const pathBar = text('div', null, 'path-finder-bar');
    pathBar.append(text('span', 'SHORTEST-PATH LINK FINDER', 'eyebrow'));
    const selFrom = document.createElement('select');
    selFrom.setAttribute('aria-label', 'Shortest path source entity');
    const selTo = document.createElement('select');
    selTo.setAttribute('aria-label', 'Shortest path target entity');
    all.slice(0, 80).forEach((n, idx) => {
      const o1 = text('option', `${n.kind.toUpperCase()}: ${n.label.slice(0, 34)}`);
      o1.value = n.id;
      const o2 = text('option', `${n.kind.toUpperCase()}: ${n.label.slice(0, 34)}`);
      o2.value = n.id;
      selFrom.append(o1);
      selTo.append(o2);
      if (!graphPathFrom && idx === 0) graphPathFrom = n.id;
      if (!graphPathTo && idx === Math.min(all.length - 1, 2)) graphPathTo = n.id;
    });
    selFrom.value = graphPathFrom;
    selTo.value = graphPathTo;
    const findBtn = text('button', 'Trace Link Path', 'secondary');
    findBtn.type = 'button';
    findBtn.onclick = () => {
      graphPathFrom = selFrom.value;
      graphPathTo = selTo.value;
      activePathResult = findShortestEntityPath(all, graph.edges || [], graphPathFrom, graphPathTo);
      if (!activePathResult) message('No connected path found between the selected entities.', true);
      else message(`Traced ${activePathResult.orderedIds.length - 1}-hop link path across source-backed evidence.`);
      renderView();
    };
    const clearBtn = text('button', 'Reset Path', 'secondary');
    clearBtn.type = 'button';
    clearBtn.onclick = () => {
      activePathResult = null;
      renderView();
    };
    pathBar.append(selFrom, text('span', 'TO', 'mono muted'), selTo, findBtn, clearBtn);
    if (activePathResult) {
      const chainLabels = activePathResult.orderedIds.map(id => all.find(n => n.id === id)?.label || id).join(' -> ');
      pathBar.append(text('span', `Path: ${chainLabels}`, 'mono'));
    }
    view.append(pathBar);
  }

  const NODE_W = 300, COL = NODE_W + 60, ROW = 75, MAXLEN = 40;
  const filteredNodes = all.filter(n => graphKindFilter === 'all' ? (n.kind !== 'observation' || all.length <= 25) : (n.kind === graphKindFilter || n.id === all[0]?.id)).slice(0, 80);
  const positions = new Map();
  const columns = new Map();
  categories.forEach(k => columns.set(k, []));
  filteredNodes.forEach(n => columns.get(n.kind)?.push(n));

  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  const nonempty = categories.filter(k => columns.get(k).length);
  const width = Math.max(1000, 30 + nonempty.length * COL);
  let height = 440;
  nonempty.forEach((kind, i) => {
    const group = columns.get(kind);
    height = Math.max(height, group.length * ROW + 100);
    group.forEach((n, j) => positions.set(n.id, {x: 30 + i * COL, y: 65 + j * ROW}));
  });
  svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
  svg.setAttribute('role', 'img');
  svg.setAttribute('aria-label', 'Source-backed entity relationships');
  svg.style.minWidth = Math.round(width * graphZoom) + 'px';

  (graph.edges || []).forEach((edge, idx) => {
    const a = positions.get(edge.source), b = positions.get(edge.target);
    if (!a || !b) return;
    const path = document.createElementNS(ns, 'path');
    const x1 = a.x + NODE_W, y1 = a.y + 18, x2 = b.x, y2 = b.y + 18;
    path.setAttribute('d', `M${x1},${y1} C${x1 + 45},${y1} ${x2 - 45},${y2} ${x2},${y2}`);
    const isHighlighted = activePathResult?.edgeIndices?.has(idx);
    path.setAttribute('class', 'graph-edge' + (isHighlighted ? ' path-highlight' : ''));
    const title = document.createElementNS(ns, 'title');
    title.textContent = edge.kind + ' · ' + edge.evidence_ids.length + ' source-backed observations';
    path.append(title);
    svg.append(path);
  });
  nonempty.forEach((kind, i) => {
    const title = document.createElementNS(ns, 'text');
    title.setAttribute('x', 30 + i * COL);
    title.setAttribute('y', 30);
    title.setAttribute('class', 'graph-label');
    title.textContent = kind.toUpperCase();
    svg.append(title);
  });
  filteredNodes.forEach(node => {
    const p = positions.get(node.id);
    const g = document.createElementNS(ns, 'g');
    g.setAttribute('transform', `translate(${p.x},${p.y})`);
    g.setAttribute('class', 'graph-node-group');
    g.onclick = () => showEntityTransformInspector(node);
    const rect = document.createElementNS(ns, 'rect');
    rect.setAttribute('width', NODE_W);
    rect.setAttribute('height', 38);
    rect.setAttribute('rx', 10);
    rect.setAttribute('ry', 10);
    const isNodeHighlighted = activePathResult?.nodeIds?.has(node.id);
    rect.setAttribute('class', 'graph-node' + (isNodeHighlighted ? ' path-highlight' : ''));
    const label = document.createElementNS(ns, 'text');
    label.setAttribute('x', 12);
    label.setAttribute('y', 24);
    label.setAttribute('class', 'graph-node-label');
    label.textContent = node.label.length > MAXLEN ? node.label.slice(0, MAXLEN - 1) + '…' : node.label;
    const title = document.createElementNS(ns, 'title');
    title.textContent = `${node.label} (Click to inspect & run transform)`;
    g.append(rect, label, title);
    svg.append(g);
  });
  attachInteractiveSvgPanZoom(svg);
  const canvas = text('div', null, 'panel graph-canvas');
  canvas.append(svg);
  view.append(canvas);
  if (filteredNodes.length < all.length) {
    view.append(text('p', `Showing ${filteredNodes.length} entity nodes. Full graph: ${all.length} nodes, ${graph.edges.length} edges; use filter pills above or export JSON for full graph.`, 'notice'));
  }
  const panelBox = panel('Relationships and supporting evidence');
  (graph.edges || []).slice(0, 120).forEach(e => {
    const a = all.find(n => n.id === e.source), b = all.find(n => n.id === e.target);
    const row = text('div', null, 'requirement');
    row.append(text('h3', `${a?.label} · ${e.kind} · ${b?.label}`));
    e.evidence_ids.forEach(id => {
      const fact = brief.facts.find(f => f.fact_id === id);
      if (fact) row.append(sourceButton(fact));
    });
    panelBox.body.append(row);
  });
  view.append(panelBox.root);
  renderSourceConnectionChart(view);
}

function showSourceAdapterInspector(sourceName, sourceFacts) {
  const root = $('#source-content');
  if (!root || !brief) return;
  root.replaceChildren(text('h2', `SOURCE ADAPTER · ${sourceName.toUpperCase()}`));
  const distinctSubjects = [...new Set(sourceFacts.map(f => f.subject).filter(Boolean))];
  const distinctValues = [...new Set(sourceFacts.map(f => f.value).filter(Boolean))];
  const grades = [...new Set(sourceFacts.map(f => f.admiralty).filter(Boolean))];
  const dl = document.createElement('dl');
  dl.append(
    text('dt', 'Intelligence Source'), text('dd', sourceName),
    text('dt', 'Target Seed'), text('dd', subjectLabel()),
    text('dt', 'Connected Facts'), text('dd', String(sourceFacts.length)),
    text('dt', 'Connected Subjects'), text('dd', distinctSubjects.slice(0, 8).join(', ') || '—'),
    text('dt', 'Admiralty Grades'), text('dd', grades.join(', ') || 'C3'),
    text('dt', 'Collection Mode'), text('dd', sourceFacts[0]?.collection_mode || 'passive')
  );
  root.append(dl);

  const fBox = text('div', null, 'export-actions exposure-citations');
  sourceFacts.slice(0, 18).forEach(f => {
    const b = text('button', `${f.admiralty || 'C3'} · ${f.attribute.split('.').pop()}: ${String(f.value).slice(0, 24)}`, 'source-button');
    b.type = 'button';
    b.onclick = () => showSource(f);
    fBox.append(b);
  });
  root.append(fBox);

  const pivotCandidate = distinctValues.find(v => isPivotableValue(v, 'domain'));
  if (pivotCandidate) {
    const actions = text('div', null, 'export-actions source-pivot-bar');
    const pivotBtn = text('button', `Run Transform on ${pivotCandidate}`, 'primary');
    pivotBtn.type = 'button';
    pivotBtn.onclick = () => {
      $('#source-dialog').close();
      setWorkspaceView('command');
      if ($('#seed-kind')) $('#seed-kind').value = 'auto';
      $('#domain').value = pivotCandidate;
      updateSeedInputNotice();
      $('#investigate').requestSubmit?.();
    };
    actions.append(pivotBtn);
    root.append(actions);
  }
  syncContextDrawer(`SOURCE ADAPTER · ${sourceName.toUpperCase()}`);
  $('#source-dialog').showModal();
}

function renderSourceConnectionChart(view) {
  const facts = brief?.facts || [];
  if (!facts.length) return;

  // Group facts and connected entities by OSINT source adapter
  const bySource = new Map();
  facts.forEach(f => {
    const src = f.source || f.retrieved_by || 'osint';
    if (!bySource.has(src)) bySource.set(src, []);
    bySource.get(src).push(f);
  });
  const sources = [...bySource.entries()].sort((a, b) => b[1].length - a[1].length);

  const chartPanel = panel('Source Connection Chart · Target Hub, Intelligence Sources & Connected Entities');
  chartPanel.body.append(
    text('p', 'Interactive radial hub-and-spoke chart showing every OSINT source connected to the target seed (inner orbit) and the discovered entities/observations connected to each source (outer orbit). Click any source or entity node to inspect its records.', 'notice')
  );

  // 1. Radial Hub-and-Spoke SVG Chart (Target Center -> OSINT Sources -> Connected Entities)
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  const W = 1000, H = 520, CX = 500, CY = 260, R_INNER = 122, R_OUTER = 218;
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
  svg.setAttribute('role', 'img');
  svg.setAttribute('aria-label', 'Source connection hub and spoke chart');

  [R_INNER, R_OUTER].forEach(r => {
    const orbit = document.createElementNS(ns, 'circle');
    orbit.setAttribute('cx', CX);
    orbit.setAttribute('cy', CY);
    orbit.setAttribute('r', r);
    orbit.setAttribute('class', 'radial-orbit');
    svg.append(orbit);
  });

  const sourceCoords = [];
  const outerEntities = [];

  sources.forEach(([srcName, sFacts], idx) => {
    const angle = (2 * Math.PI * idx) / Math.max(1, sources.length) - Math.PI / 2;
    const sx = Math.round(CX + R_INNER * Math.cos(angle));
    const sy = Math.round(CY + R_INNER * Math.sin(angle));
    sourceCoords.push({srcName, sFacts, sx, sy, angle});

    // Pick up to 4 distinct representative connected entities per source for the outer orbit
    const uniqueVals = [];
    const seenV = new Set();
    for (const f of sFacts) {
      const label = `${f.attribute.split('.').pop()}: ${String(f.value).slice(0, 20)}`;
      if (!seenV.has(label)) {
        seenV.add(label);
        uniqueVals.push({label, rawVal: String(f.value), attr: f.attribute, fact: f});
      }
      if (uniqueVals.length >= Math.min(5, Math.max(2, Math.ceil(20 / Math.max(1, sources.length))))) break;
    }
    const spread = (Math.PI * 1.35) / Math.max(1, sources.length);
    uniqueVals.forEach((ent, eIdx) => {
      const offset = uniqueVals.length === 1 ? 0 : ((eIdx / (uniqueVals.length - 1)) - 0.5) * spread;
      const eAngle = angle + offset;
      const ex = Math.round(CX + R_OUTER * Math.cos(eAngle));
      const ey = Math.round(CY + R_OUTER * Math.sin(eAngle));
      outerEntities.push({sx, sy, ex, ey, eAngle, ...ent});
    });
  });

  // Draw inner spokes (Center Target Hub -> OSINT Source)
  sourceCoords.forEach(({sx, sy}) => {
    const line = document.createElementNS(ns, 'line');
    line.setAttribute('x1', CX);
    line.setAttribute('y1', CY);
    line.setAttribute('x2', sx);
    line.setAttribute('y2', sy);
    line.setAttribute('class', 'radial-spoke-source');
    svg.append(line);
  });

  // Draw outer spokes (OSINT Source -> Connected Entity)
  outerEntities.forEach(({sx, sy, ex, ey}) => {
    const path = document.createElementNS(ns, 'path');
    const mx = Math.round((sx + ex) / 2);
    const my = Math.round((sy + ey) / 2);
    path.setAttribute('d', `M${sx},${sy} Q${mx},${my} ${ex},${ey}`);
    path.setAttribute('class', 'radial-spoke-entity');
    svg.append(path);
  });

  // Draw Outer Connected Entity Nodes
  outerEntities.forEach(ent => {
    const g = document.createElementNS(ns, 'g');
    g.setAttribute('transform', `translate(${ent.ex},${ent.ey})`);
    g.setAttribute('class', 'radial-entity-group');
    g.onclick = () => showSource(ent.fact);

    const c = document.createElementNS(ns, 'circle');
    c.setAttribute('r', '7');
    c.setAttribute('class', 'radial-entity-node');

    const isLeft = Math.cos(ent.eAngle) < -0.15;
    const t = document.createElementNS(ns, 'text');
    t.setAttribute('x', isLeft ? '-11' : '11');
    t.setAttribute('y', '3');
    if (isLeft) t.setAttribute('text-anchor', 'end');
    t.setAttribute('class', 'radial-sublabel');
    t.textContent = ent.label;

    const title = document.createElementNS(ns, 'title');
    title.textContent = `${ent.fact.attribute} = ${ent.rawVal} (Source: ${ent.fact.source})`;
    g.append(c, t, title);
    svg.append(g);
  });

  // Draw Inner OSINT Source Adapter Nodes
  sourceCoords.forEach(({srcName, sFacts, sx, sy}) => {
    const g = document.createElementNS(ns, 'g');
    g.setAttribute('transform', `translate(${sx - 54},${sy - 17})`);
    g.setAttribute('class', 'radial-source-group');
    g.onclick = () => showSourceAdapterInspector(srcName, sFacts);

    const rect = document.createElementNS(ns, 'rect');
    rect.setAttribute('width', '108');
    rect.setAttribute('height', '34');
    rect.setAttribute('rx', '10');
    rect.setAttribute('class', 'radial-source-node');

    const t1 = document.createElementNS(ns, 'text');
    t1.setAttribute('x', '54');
    t1.setAttribute('y', '15');
    t1.setAttribute('text-anchor', 'middle');
    t1.setAttribute('class', 'radial-label');
    t1.textContent = srcName.slice(0, 14).toUpperCase();

    const t2 = document.createElementNS(ns, 'text');
    t2.setAttribute('x', '54');
    t2.setAttribute('y', '27');
    t2.setAttribute('text-anchor', 'middle');
    t2.setAttribute('class', 'radial-sublabel');
    t2.textContent = `${sFacts.length} connected`;

    const title = document.createElementNS(ns, 'title');
    title.textContent = `${srcName}: ${sFacts.length} connected observation(s). Click to inspect all entities from this source.`;
    g.append(rect, t1, t2, title);
    svg.append(g);
  });

  // Draw Center Target Seed Hub
  const hubG = document.createElementNS(ns, 'g');
  hubG.setAttribute('transform', `translate(${CX - 72},${CY - 22})`);
  const hubRect = document.createElementNS(ns, 'rect');
  hubRect.setAttribute('width', '144');
  hubRect.setAttribute('height', '44');
  hubRect.setAttribute('rx', '14');
  hubRect.setAttribute('class', 'radial-hub-node');
  const hubT1 = document.createElementNS(ns, 'text');
  hubT1.setAttribute('x', '72');
  hubT1.setAttribute('y', '18');
  hubT1.setAttribute('text-anchor', 'middle');
  hubT1.setAttribute('class', 'radial-sublabel');
  hubT1.textContent = 'TARGET SEED';
  const hubT2 = document.createElementNS(ns, 'text');
  hubT2.setAttribute('x', '72');
  hubT2.setAttribute('y', '33');
  hubT2.setAttribute('text-anchor', 'middle');
  hubT2.setAttribute('class', 'radial-label');
  hubT2.setAttribute('class', 'radial-label');
  hubT2.textContent = String(subjectLabel()).slice(0, 18);
  hubG.append(hubRect, hubT1, hubT2);
  svg.append(hubG);

  attachInteractiveSvgPanZoom(svg);
  const canvasWrap = text('div', null, 'source-chart-canvas');
  canvasWrap.append(svg);
  chartPanel.body.append(canvasWrap);

  // 2. Source-to-Entity Distribution Bar Chart & Connected Selectors List
  const barList = text('div', null, 'source-bar-list');
  const maxCount = Math.max(1, ...sources.map(([, list]) => list.length));
  sources.forEach(([srcName, sFacts]) => {
    const pct = Math.max(6, Math.round((sFacts.length / maxCount) * 100));
    const row = text('div', null, 'source-bar-row');
    const head = text('div', null, 'source-bar-head');
    const left = text('strong', `${srcName} · ${sFacts.length} Connected Observation${sFacts.length === 1 ? '' : 's'}`);
    const inspectBtn = text('button', `Inspect ${srcName}`, 'secondary');
    inspectBtn.type = 'button';
    inspectBtn.onclick = () => showSourceAdapterInspector(srcName, sFacts);
    head.append(left, inspectBtn);

    const track = text('div', null, 'source-bar-track');
    const fill = text('div', null, 'source-bar-fill');
    fill.style.width = `${pct}%`;
    track.append(fill);

    const pills = text('div', null, 'source-connected-pills');
    sFacts.slice(0, 10).forEach(f => {
      const b = text('button', `${f.admiralty || 'C3'} · ${f.attribute.split('.').pop()}: ${String(f.value).slice(0, 28)}`, 'source-button');
      b.type = 'button';
      b.onclick = () => showSource(f);
      pills.append(b);
    });
    row.append(head, track, pills);
    barList.append(row);
  });
  chartPanel.body.append(barList);
  view.append(chartPanel.root);
}

// Simplified continental silhouettes on a 1000x500 equirectangular projection
const WORLD_CONTINENT_PATHS = [
  // North America
  'M85,68 L175,58 L262,72 L308,118 L272,165 L235,198 L210,224 L178,205 L145,168 L95,124 Z',
  // Greenland
  'M330,42 L398,38 L412,76 L356,88 Z',
  // South America
  'M245,238 L318,252 L352,304 L328,392 L292,438 L268,385 L242,302 Z',
  // Europe
  'M458,72 L548,62 L588,92 L572,146 L516,158 L462,144 L448,108 Z',
  // Africa
  'M452,168 L545,168 L596,225 L588,318 L546,386 L504,376 L478,298 L442,232 Z',
  // Asia
  'M588,68 L765,58 L878,86 L892,155 L836,224 L758,246 L685,228 L612,188 L582,135 Z',
  // Japan & SE Asia islands
  'M832,248 L882,258 L894,296 L842,292 Z',
  // Australia & New Zealand
  'M776,326 L882,322 L904,382 L846,412 L782,388 Z',
  'M924,404 L952,412 L944,436 L918,426 Z',
];

function showEntityTransformInspector(node) {
  const root = $('#source-content');
  if (!root || !brief) return;
  root.replaceChildren(text('h2', `${node.kind.toUpperCase()} · ${node.label}`));
  const dl = document.createElement('dl');
  const connectedEdges = (brief.graph?.edges || []).filter(e => e.source === node.id || e.target === node.id);
  const factIds = new Set();
  connectedEdges.forEach(e => (e.evidence_ids || []).forEach(id => factIds.add(id)));
  const relatedFacts = (brief.facts || []).filter(f => factIds.has(f.fact_id) || f.subject === node.label || f.value === node.label);

  dl.append(
    text('dt', 'Entity Label'), text('dd', node.label),
    text('dt', 'Entity Kind'), text('dd', node.kind),
    text('dt', 'Connected Links'), text('dd', String(connectedEdges.length)),
    text('dt', 'Supporting Facts'), text('dd', String(relatedFacts.length))
  );
  root.append(dl);

  if (relatedFacts.length) {
    const fBox = text('div', null, 'export-actions exposure-citations');
    relatedFacts.slice(0, 12).forEach(f => fBox.append(sourceButton(f)));
    root.append(fBox);
  }

  const actions = text('div', null, 'export-actions source-pivot-bar');
  const expandBtn = text('button', 'Expand Node in Place', 'secondary');
  expandBtn.type = 'button';
  expandBtn.onclick = () => expandEntityNodeInPlace(node.label);
  actions.append(expandBtn);

  if (isPivotableValue(node.label, node.kind)) {
    const pivotBtn = text('button', `Run Transform: Investigate ${node.label}`, 'primary');
    pivotBtn.type = 'button';
    pivotBtn.onclick = () => {
      $('#source-dialog').close();
      setWorkspaceView('command');
      if ($('#seed-kind')) $('#seed-kind').value = 'auto';
      $('#domain').value = node.label;
      updateSeedInputNotice();
      $('#investigate').requestSubmit?.();
    };
    actions.append(pivotBtn);
  }
  root.append(actions);
  syncContextDrawer(`${node.kind.toUpperCase()} · ${node.label}`);
  $('#source-dialog').showModal();
}

function showGeoNodeInspector(pt) {
  const root = $('#source-content');
  if (!root || !brief) return;
  root.replaceChildren(text('h2', `HOST NODE · ${pt.ip}`));
  const dl = document.createElement('dl');
  for (const [k, v] of Object.entries({
    'IP Address': pt.ip,
    'Primary Hostname': pt.label,
    'All Hostnames': (pt.hostnames || []).join(', ') || pt.ip,
    'Location': `${pt.city || pt.country_name} (${pt.country})`,
    'Coordinates': `${pt.lat}, ${pt.lon}`,
    'Organization / ISP': pt.org || 'Unknown',
    'ASN': pt.asn || 'Unspecified',
    'CIDR Block': pt.cidr || '—',
    'Open Ports': (pt.ports || []).join(', ') || 'None observed',
    'CVEs / Advisories': (pt.vulns || []).join(', ') || 'None observed',
    'CPE Fingerprints': (pt.cpes || []).join(', ') || 'None observed',
  })) {
    dl.append(text('dt', k), text('dd', v));
  }
  root.append(dl);

  const facts = (brief.facts || []).filter(f => (pt.fact_ids || []).includes(f.fact_id) || f.subject === pt.ip || f.value === pt.ip);
  if (facts.length) {
    const fBox = text('div', null, 'export-actions exposure-citations');
    facts.slice(0, 12).forEach(f => fBox.append(sourceButton(f)));
    root.append(fBox);
  }

  const actions = text('div', null, 'export-actions source-pivot-bar');
  const expandBtn = text('button', 'Expand Host in Place', 'secondary');
  expandBtn.type = 'button';
  expandBtn.onclick = () => expandEntityNodeInPlace(pt.ip);
  const pivotBtn = text('button', `Run Shodan / Host Transform on ${pt.ip}`, 'primary');
  pivotBtn.type = 'button';
  pivotBtn.onclick = () => {
    $('#source-dialog').close();
    setWorkspaceView('command');
    if ($('#seed-kind')) $('#seed-kind').value = 'ip';
    $('#domain').value = pt.ip;
    updateSeedInputNotice();
    $('#investigate').requestSubmit?.();
  };
  actions.append(expandBtn, pivotBtn);
  root.append(actions);
  syncContextDrawer(`HOST NODE · ${pt.ip}`);
  $('#source-dialog').showModal();
}

function renderGeoMap(view) {
  const geo = brief.geo_map || {points: [], arcs: [], summary: {total_nodes: 0, countries_count: 0, providers_count: 0, open_ports_count: 0, vulnerable_nodes_count: 0, countries: [], providers: []}};
  const points = geo.points || [];
  const summary = geo.summary || {};

  const toolbar = text('div', null, 'graph-toolbar');
  toolbar.append(
    text('p', 'Offline vector Geo-IP & ASN topology map. Plots discovered IPv4/IPv6 infrastructure, Shodan open ports/CVEs, and hosting jurisdictions locally without external map-tile requests.', 'notice')
  );
  const actions = text('div', null, 'export-actions');
  const btnGraphml = text('button', 'Export Maltego (.graphml)', 'secondary');
  btnGraphml.type = 'button';
  btnGraphml.onclick = () => downloadMaltego('maltego.graphml');
  const btnCsv = text('button', 'Export Maltego (.csv)', 'secondary');
  btnCsv.type = 'button';
  btnCsv.onclick = () => downloadMaltego('maltego.csv');
  actions.append(btnGraphml, btnCsv);
  toolbar.append(actions);
  view.append(toolbar);

  // Summary strip
  const sumGrid = text('div', null, 'posture-grid');
  [
    ['MAPPED IP NODES', String(summary.total_nodes || 0), 'Resolved infrastructure hosts'],
    ['COUNTRIES', String(summary.countries_count || 0), 'Distinct hosting jurisdictions'],
    ['ASN / PROVIDERS', String(summary.providers_count || 0), 'Network & cloud operators'],
    ['OPEN PORTS', String(summary.open_ports_count || 0), 'Shodan / InternetDB ports'],
    ['CVE HOSTS', String(summary.vulnerable_nodes_count || 0), 'Hosts with advisory matches'],
  ].forEach(([title, val, sub]) => {
    const card = text('div', null, 'posture-card');
    const top = text('div', null, 'posture-card-top');
    top.append(text('h3', title), text('span', val, 'grade-badge'));
    card.append(top, text('p', sub));
    sumGrid.append(card);
  });
  view.append(sumGrid);

  // World SVG Map Canvas
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('viewBox', '0 0 1000 500');
  svg.setAttribute('role', 'img');
  svg.setAttribute('aria-label', 'Global Geo-IP and ASN infrastructure map');

  // Graticule lines
  for (let x = 100; x < 1000; x += 100) {
    const line = document.createElementNS(ns, 'line');
    line.setAttribute('x1', x);
    line.setAttribute('y1', 0);
    line.setAttribute('x2', x);
    line.setAttribute('y2', 500);
    line.setAttribute('class', 'geo-graticule');
    svg.append(line);
  }
  for (let y = 83; y < 500; y += 83) {
    const line = document.createElementNS(ns, 'line');
    line.setAttribute('x1', 0);
    line.setAttribute('y1', y);
    line.setAttribute('x2', 1000);
    line.setAttribute('y2', y);
    line.setAttribute('class', y === 249 ? 'geo-equator' : 'geo-graticule');
    svg.append(line);
  }

  // Continental silhouettes
  WORLD_CONTINENT_PATHS.forEach(d => {
    const p = document.createElementNS(ns, 'path');
    p.setAttribute('d', d);
    p.setAttribute('class', 'geo-continent');
    svg.append(p);
  });

  // Geodesic arcs between infrastructure nodes
  (geo.arcs || []).forEach(arc => {
    const path = document.createElementNS(ns, 'path');
    const mx = (arc.x1 + arc.x2) / 2;
    const my = Math.min(arc.y1, arc.y2) - 42;
    path.setAttribute('d', `M${arc.x1},${arc.y1} Q${mx},${my} ${arc.x2},${arc.y2}`);
    path.setAttribute('class', 'geo-arc');
    svg.append(path);
  });

  // Plot each IP pin
  points.forEach(pt => {
    const g = document.createElementNS(ns, 'g');
    g.setAttribute('transform', `translate(${pt.x},${pt.y})`);
    g.setAttribute('class', `geo-pin ${pt.severity || 'normal'}`);
    g.onclick = () => showGeoNodeInspector(pt);

    const halo = document.createElementNS(ns, 'circle');
    halo.setAttribute('r', '14');
    halo.setAttribute('class', 'geo-pin-halo');

    const core = document.createElementNS(ns, 'circle');
    core.setAttribute('r', '5.5');
    core.setAttribute('class', 'geo-pin-core');

    const lbl = document.createElementNS(ns, 'text');
    lbl.setAttribute('x', '9');
    lbl.setAttribute('y', '3');
    lbl.setAttribute('class', 'geo-pin-label');
    lbl.textContent = `${pt.ip} (${pt.country})`;

    const title = document.createElementNS(ns, 'title');
    title.textContent = `${pt.ip} · ${pt.city} (${pt.country_name}) · ${pt.org} · Ports: ${(pt.ports || []).join(', ') || 'none'}`;

    g.append(halo, core, lbl, title);
    svg.append(g);
  });

  attachInteractiveSvgPanZoom(svg);
  const mapWrap = text('div', null, 'geo-map-canvas');
  mapWrap.append(svg);
  view.append(mapWrap);

  if (!points.length) {
    view.append(empty('No routable IPv4/IPv6 hosts observed in this run.', 'Run a domain, website, or IP investigation with DNS Posture, Shodan InternetDB, or Passive DNS enabled to populate the global infrastructure map.'));
    renderSourceConnectionChart(view);
    return;
  }

  // Country & Provider breakdown + Host cards
  const breakdownGrid = text('div', null, 'overview-grid');
  const countryBox = panel('Jurisdictions & Geographic Footprint');
  (summary.countries || []).forEach(c => {
    const row = text('div', null, 'requirement');
    row.append(text('h3', `${c.name} (${c.code}) — ${c.count} host${c.count === 1 ? '' : 's'}`));
    countryBox.body.append(row);
  });
  const providerBox = panel('ASN & Cloud Hosting Concentration');
  (summary.providers || []).forEach(p => {
    const row = text('div', null, 'requirement');
    row.append(text('h3', `${p.name} — ${p.count} host${p.count === 1 ? '' : 's'}`));
    providerBox.body.append(row);
  });
  breakdownGrid.append(countryBox.root, providerBox.root);
  view.append(breakdownGrid);

  const hostsBox = panel('Mapped Host Nodes · Click to Inspect or Pivot');
  const hostGrid = text('div', null, 'geo-host-grid');
  points.forEach(pt => {
    const card = text('div', null, 'posture-card');
    const top = text('div', null, 'posture-card-top');
    top.append(text('h3', `${pt.ip} · ${pt.country}`), text('span', pt.asn, 'tag'));
    card.append(
      top,
      text('p', `${pt.org} · ${pt.city} (${pt.lat}, ${pt.lon})`),
      text('p', `Hostnames: ${(pt.hostnames || []).join(', ') || pt.label}`),
      text('p', `Ports: ${(pt.ports || []).join(', ') || 'none'}${pt.vulns?.length ? ' · CVEs: ' + pt.vulns.join(', ') : ''}`)
    );
    const inspectBtn = text('button', 'Inspect & Run Transform', 'secondary');
    inspectBtn.type = 'button';
    inspectBtn.onclick = () => showGeoNodeInspector(pt);
    card.append(inspectBtn);
    hostGrid.append(card);
  });
  hostsBox.body.append(hostGrid);
  view.append(hostsBox.root);
  renderSourceConnectionChart(view);
}

async function downloadMaltego(fmt) {
  if (!brief) return;
  try {
    const data = await api(`/api/runs/${encodeURIComponent(brief.run_id)}/${fmt}`);
    const url = URL.createObjectURL(new Blob([data.content], {type: data.content_type || 'text/plain;charset=utf-8'}));
    const a = document.createElement('a');
    a.href = url;
    a.download = data.filename || `find3r-${brief.run_id}-${fmt}`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    const labelMap = {
      'maltego.graphml': 'Maltego GraphML (.graphml)',
      'maltego.csv': 'Maltego Entity Table (.csv)',
      'stix.json': 'OASIS STIX 2.1 Threat Intelligence Bundle (.json)',
      'dossier.html': 'Print-Ready Executive HTML Dossier (.html)',
    };
    message(`Exported ${labelMap[fmt] || fmt} for ${subjectLabel()}.`);
  } catch (err) {
    message(err.message, true);
  }
}

if ($('#export-maltego-graphml')) $('#export-maltego-graphml').onclick = () => downloadMaltego('maltego.graphml');
if ($('#export-maltego-csv')) $('#export-maltego-csv').onclick = () => downloadMaltego('maltego.csv');
if ($('#export-stix')) $('#export-stix').onclick = () => downloadMaltego('stix.json');
if ($('#export-dossier-html')) $('#export-dossier-html').onclick = () => downloadMaltego('dossier.html');

// =========================================================================
// OPERATIONS & TRADECRAFT WORKSPACE (Diff Engine, Case Fusion, Pinboard, ACH)
// =========================================================================
let lastDiffData = null;
let loadedCaseDossier = null;

function renderOperationsTab(view) {
  const ops = snapshot?.operations || {cases: [], pins: [], notes: [], hypotheses: [], ach_ranked: []};
  const allRuns = snapshot?.runs || [];

  // 1. Temporal Attack Surface Diff ("Run Delta Engine")
  const diffPanel = panel('Temporal Attack Surface Diff · Run Delta Engine');
  diffPanel.body.append(
    text('p', 'Compare any two stored investigations to detect new subdomains, IP/ASN shifts, opened/closed Shodan ports, new CVE advisories, and posture grade drift.', 'notice')
  );
  const diffBar = text('div', null, 'ops-diff-bar');
  const selBase = document.createElement('select');
  selBase.setAttribute('aria-label', 'Baseline investigation run');
  const selCurr = document.createElement('select');
  selCurr.setAttribute('aria-label', 'Comparison investigation run');
  allRuns.forEach((r, idx) => {
    const label = `${subjectLabel(r)} · ${r.id.slice(0, 8)} (${date(r.started_at)})`;
    const o1 = text('option', `BASELINE: ${label}`);
    o1.value = r.id;
    const o2 = text('option', `CURRENT: ${label}`);
    o2.value = r.id;
    selBase.append(o1);
    selCurr.append(o2);
    if (idx === Math.min(1, allRuns.length - 1)) selBase.value = r.id;
  });
  if (brief?.run_id && allRuns.some(r => r.id === brief.run_id)) {
    selCurr.value = brief.run_id;
  }
  const runDiffBtn = text('button', 'Compute Attack Surface Delta', 'primary');
  runDiffBtn.type = 'button';
  const diffResultWrap = text('div');

  const renderDiffResult = (diff) => {
    diffResultWrap.replaceChildren();
    if (!diff) return;
    const s = diff.summary || {};
    const scoreDeltaStr = s.score_delta === null || s.score_delta === undefined
      ? 'N/A'
      : (s.score_delta >= 0 ? `+${s.score_delta}` : String(s.score_delta));
    const cards = text('div', null, 'posture-grid');
    [
      ['POSTURE GRADE DRIFT', `${s.baseline_grade || 'N/A'} -> ${s.current_grade || 'N/A'}`, `Score Delta: ${scoreDeltaStr}`],
      ['ADDED OBSERVATIONS', `+${s.added_count || 0}`, 'Newly appeared selectors & facts'],
      ['REMOVED OBSERVATIONS', `-${s.removed_count || 0}`, 'Decommissioned or absent records'],
      ['PORT / CVE DRIFT', String((diff.host_port_drift || []).length), 'Hosts with port or advisory changes'],
    ].forEach(([lbl, val, sub]) => {
      const c = text('div', null, 'posture-card');
      const top = text('div', null, 'posture-card-top');
      top.append(text('h3', lbl), text('span', val, 'grade-badge'));
      c.append(top, text('p', sub));
      cards.append(c);
    });
    diffResultWrap.append(cards);

    if ((diff.host_port_drift || []).length) {
      diff.host_port_drift.forEach(drift => {
        const row = text('div', null, 'requirement');
        row.append(
          text('h3', `Host ${drift.ip} Port/CVE Drift`),
          text('p', `Added Ports: ${(drift.added_ports || []).join(', ') || 'none'} · Removed Ports: ${(drift.removed_ports || []).join(', ') || 'none'} · Added CVEs: ${(drift.added_vulns || []).join(', ') || 'none'}`, 'mono')
        );
        diffResultWrap.append(row);
      });
    }

    const deltaCols = text('div', null, 'ops-grid');
    const addedBox = text('div', null, 'requirement');
    addedBox.append(text('span', `+ ${s.added_count || 0} ADDED`, 'delta-badge-add'), text('h3', 'Newly Observed Attack Surface'));
    (diff.added_facts || []).slice(0, 15).forEach(f => {
      addedBox.append(text('p', `[+] ${f.subject} · ${f.attribute} = ${f.value}`, 'mono'));
    });
    if (!(diff.added_facts || []).length) addedBox.append(text('p', 'No added facts between selected runs.', 'notice'));

    const removedBox = text('div', null, 'requirement');
    removedBox.append(text('span', `- ${s.removed_count || 0} REMOVED`, 'delta-badge-rem'), text('h3', 'Removed / Absent Observations'));
    (diff.removed_facts || []).slice(0, 15).forEach(f => {
      removedBox.append(text('p', `[-] ${f.subject} · ${f.attribute} = ${f.value}`, 'mono muted'));
    });
    if (!(diff.removed_facts || []).length) removedBox.append(text('p', 'No removed facts between selected runs.', 'notice'));

    deltaCols.append(addedBox, removedBox);
    diffResultWrap.append(deltaCols);
  };

  runDiffBtn.onclick = async () => {
    if (!selBase.value || !selCurr.value) return;
    runDiffBtn.disabled = true;
    runDiffBtn.textContent = 'Computing Delta…';
    try {
      lastDiffData = await api(`/api/runs/${encodeURIComponent(selBase.value)}/diff/${encodeURIComponent(selCurr.value)}`);
      renderDiffResult(lastDiffData);
      message(`Computed temporal delta between ${selBase.value.slice(0, 8)} and ${selCurr.value.slice(0, 8)}.`);
    } catch (err) {
      message(err.message, true);
    } finally {
      runDiffBtn.disabled = false;
      runDiffBtn.textContent = 'Compute Attack Surface Delta';
    }
  };
  diffBar.append(selBase, selCurr, runDiffBtn);
  diffPanel.body.append(diffBar, diffResultWrap);
  if (lastDiffData) renderDiffResult(lastDiffData);
  view.append(diffPanel.root);

  // 2. Multi-Run Operation Cases & Cross-Target Shared Infrastructure Correlation
  const casePanel = panel('Operation Cases · Multi-Run Dossier Fusion & Cross-Target Correlation');
  casePanel.body.append(
    text('p', 'Group multiple domain, email, username, and IP investigations into a unified Operation Case to automatically detect shared IPs, shared ASNs, shared nameservers, and shared TLS certificate issuers across targets.', 'notice')
  );
  const caseForm = text('div', null, 'ops-diff-bar');
  const titleInp = document.createElement('input');
  titleInp.type = 'text';
  titleInp.placeholder = 'Operation Case Title (e.g., OP-AURORA Vendor Assessment)';
  const clientInp = document.createElement('input');
  clientInp.type = 'text';
  clientInp.placeholder = 'Mission / Client Tag';
  const createCaseBtn = text('button', 'Create / Fuse Operation Case', 'primary');
  createCaseBtn.type = 'button';

  const runCheckboxes = text('div', null, 'source-connected-pills');
  allRuns.slice(0, 16).forEach((r, idx) => {
    const lbl = text('label', null, 'contact-option');
    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.value = r.id;
    cb.checked = idx < 3 || r.id === brief?.run_id;
    lbl.append(cb, text('span', `${subjectLabel(r)} (${r.id.slice(0, 6)})`));
    runCheckboxes.append(lbl);
  });

  createCaseBtn.onclick = async () => {
    const checkedIds = [...runCheckboxes.querySelectorAll('input:checked')].map(i => i.value);
    const title = titleInp.value.trim() || `Operation ${subjectLabel()}`;
    try {
      const res = await api('/api/operations/cases', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-Workspace-Token': session},
        body: JSON.stringify({
          title,
          client: clientInp.value.trim(),
          classification: 'TLP:AMBER+STRICT',
          run_ids: checkedIds,
        }),
      });
      if (snapshot) snapshot.operations = res.operations;
      if (res.case?.id) {
        loadedCaseDossier = await api(`/api/operations/cases/${encodeURIComponent(res.case.id)}`);
      }
      message(`Saved Operation Case "${title}" with ${checkedIds.length} fused run(s).`);
      renderView();
    } catch (err) {
      message(err.message, true);
    }
  };
  const importBundleBtn = text('button', 'Import Partner Case Bundle (.json)', 'secondary');
  importBundleBtn.type = 'button';
  const fileInput = document.createElement('input');
  fileInput.type = 'file';
  fileInput.accept = '.json,application/json';
  fileInput.hidden = true;
  importBundleBtn.onclick = () => fileInput.click?.();
  fileInput.onchange = async () => {
    const file = fileInput.files?.[0];
    if (!file) return;
    try {
      const rawText = await file.text();
      const parsed = JSON.parse(rawText);
      const res = await api('/api/operations/cases/import', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-Workspace-Token': session},
        body: JSON.stringify(parsed),
      });
      if (snapshot) snapshot.operations = res.operations;
      await refresh();
      message(`Imported partner case "${res.imported?.case_title || 'Operation Case'}" (${res.imported?.imported_runs || 0} runs, ${res.imported?.imported_pins || 0} pins, ${res.imported?.imported_notes || 0} notes).`);
      renderView();
    } catch (err) {
      message(`Failed to import case bundle: ${err.message}`, true);
    }
  };
  caseForm.append(titleInp, clientInp, createCaseBtn, importBundleBtn, fileInput);
  casePanel.body.append(caseForm, runCheckboxes);

  const casesList = text('div', null, 'ops-grid');
  (ops.cases || []).forEach(c => {
    const card = text('div', null, 'posture-card');
    const top = text('div', null, 'posture-card-top');
    top.append(text('h3', c.title), text('span', `${(c.run_ids || []).length} RUNS`, 'tag'));
    card.append(top, text('p', `${c.classification || 'TLP:AMBER'} · ${c.client || 'Internal Intel'} · Updated ${date(c.updated_at)}`, 'mono muted'));
    const actions = text('div', null, 'export-actions');
    const fuseBtn = text('button', 'Fuse & Correlate Case', 'secondary');
    fuseBtn.type = 'button';
    fuseBtn.onclick = async () => {
      try {
        loadedCaseDossier = await api(`/api/operations/cases/${encodeURIComponent(c.id)}`);
        message(`Correlated ${loadedCaseDossier.runs_count} runs in "${c.title}": ${(loadedCaseDossier.shared_correlations || []).length} cross-target overlap(s) found.`);
        renderView();
      } catch (err) {
        message(err.message, true);
      }
    };
    const loadFusedBtn = text('button', 'Open Fused Graph & Map', 'primary');
    loadFusedBtn.type = 'button';
    loadFusedBtn.onclick = async () => {
      try {
        const fused = await api(`/api/operations/cases/${encodeURIComponent(c.id)}`);
        loadedCaseDossier = fused;
        brief = fused;
        $('#company-title').textContent = fused.company || c.title;
        $('#subject-kind').textContent = `FUSED OPERATION CASE · ${fused.runs_count} TARGETS`;
        setTab('graph');
        message(`Loaded fused multi-target dossier "${c.title}" (${fused.facts.length} combined observations).`);
      } catch (err) {
        message(err.message, true);
      }
    };
    const exportBundleBtn = text('button', 'Share Bundle (.json)', 'secondary');
    exportBundleBtn.type = 'button';
    exportBundleBtn.onclick = async () => {
      try {
        const bundle = await api(`/api/operations/cases/${encodeURIComponent(c.id)}/export`);
        const url = URL.createObjectURL(new Blob([JSON.stringify(bundle, null, 2)], {type: 'application/json'}));
        const a = document.createElement('a');
        a.href = url;
        a.download = `${c.id}.find3r-case.json`;
        a.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
        message(`Exported portable partner case bundle "${c.id}.find3r-case.json" (SHA-256: ${(bundle.bundle_sha256 || '').slice(0, 12)}…).`);
      } catch (err) {
        message(err.message, true);
      }
    };
    actions.append(fuseBtn, loadFusedBtn, exportBundleBtn);
    card.append(actions);
    casesList.append(card);
  });
  if ((ops.cases || []).length) casePanel.body.append(casesList);

  if (loadedCaseDossier) {
    const corrBox = text('div', null, 'requirement');
    corrBox.append(
      text('span', `${(loadedCaseDossier.shared_correlations || []).length} SHARED INFRASTRUCTURE CORRELATIONS`, 'status'),
      text('h3', `Cross-Target Overlap · ${loadedCaseDossier.case?.title || 'Operation Case'}`)
    );
    (loadedCaseDossier.shared_correlations || []).slice(0, 12).forEach(ov => {
      corrBox.append(text('p', `[${ov.attribute}] ${ov.value} — Shared across ${ov.target_count} targets: ${(ov.targets || []).join(', ')}`, 'mono'));
    });
    if (!(loadedCaseDossier.shared_correlations || []).length) {
      corrBox.append(text('p', 'No overlapping IPs, ASNs, nameservers, or TLS issuers detected across the runs in this case.', 'notice'));
    }
    casePanel.body.append(corrBox);
  }
  view.append(casePanel.root);

  // 3. Analyst Pinboard & Timestamped Tradecraft Notes
  const splitOps = text('div', null, 'ops-grid');
  const pinPanel = panel(`Analyst Pinboard (${(ops.pins || []).length})`);
  pinPanel.body.append(text('p', 'Key findings pinned from the Evidence table or Context Inspector Drawer.', 'notice'));
  if (!(ops.pins || []).length) {
    pinPanel.body.append(text('p', 'No findings pinned yet. Click any Admiralty badge (A1–C3) and select "Pin Finding to Case".', 'notice'));
  } else {
    (ops.pins || []).forEach(p => {
      const row = text('div', null, 'requirement');
      row.append(
        text('span', p.admiralty || 'B2', 'tag'),
        text('h3', `${p.subject} · ${p.attribute}`),
        text('p', String(p.value), 'mono')
      );
      const unpinBtn = text('button', 'Unpin', 'secondary');
      unpinBtn.type = 'button';
      unpinBtn.onclick = () => pinFactToOperations(p);
      row.append(unpinBtn);
      pinPanel.body.append(row);
    });
  }

  const notesPanel = panel(`Timestamped Tradecraft Notes (${(ops.notes || []).length})`);
  const noteForm = text('div', null, 'ops-diff-bar');
  const noteInput = document.createElement('input');
  noteInput.type = 'text';
  noteInput.placeholder = 'Record timestamped analyst observation or attribution assessment…';
  const addNoteBtn = text('button', 'Log Note', 'secondary');
  addNoteBtn.type = 'button';
  addNoteBtn.onclick = async () => {
    const body = noteInput.value.trim();
    if (!body) return;
    try {
      const res = await api('/api/operations/note', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-Workspace-Token': session},
        body: JSON.stringify({
          run_id: brief?.run_id || '',
          subject: subjectLabel(),
          author: operatorCallsign,
          classification: 'TLP:AMBER+STRICT',
          body,
        }),
      });
      if (snapshot) snapshot.operations = res.operations;
      noteInput.value = '';
      renderView();
    } catch (err) {
      message(err.message, true);
    }
  };
  noteForm.append(noteInput, addNoteBtn);
  notesPanel.body.append(noteForm);
  (ops.notes || []).slice(0, 12).forEach(n => {
    const item = text('div', null, 'requirement');
    item.append(
      text('span', `${n.author || 'analyst'} · ${date(n.created_at)} · ${n.classification || 'TLP:AMBER'}`, 'mono muted'),
      text('p', n.body)
    );
    notesPanel.body.append(item);
  });
  splitOps.append(pinPanel.root, notesPanel.root);
  view.append(splitOps);

  // 4. Analysis of Competing Hypotheses (ACH) Admiralty-Weighted Matrix
  const achPanel = panel('Analysis of Competing Hypotheses (ACH) · Admiralty-Weighted Matrix');
  achPanel.body.append(
    text('p', 'Evaluate competing intelligence hypotheses against collected facts weighted by Admiralty source reliability and information credibility (A1 = 1.00 through F6 = 0.20).', 'notice')
  );
  const achForm = text('div', null, 'ops-diff-bar');
  const hTitle = document.createElement('input');
  hTitle.type = 'text';
  hTitle.placeholder = 'Hypothesis (e.g., H3: Target hosts unpatched edge services)';
  const hSupp = document.createElement('input');
  hSupp.type = 'text';
  hSupp.placeholder = 'Supporting attrs/keywords (comma-separated, e.g. ip.open_port, ip.vuln)';
  const hRef = document.createElement('input');
  hRef.type = 'text';
  hRef.placeholder = 'Refuting attrs/keywords (comma-separated, e.g. dnssec.status)';
  const addHypBtn = text('button', 'Add Hypothesis', 'secondary');
  addHypBtn.type = 'button';
  addHypBtn.onclick = async () => {
    if (!hTitle.value.trim()) return;
    try {
      const res = await api('/api/operations/hypothesis', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-Workspace-Token': session},
        body: JSON.stringify({
          title: hTitle.value.trim(),
          supporting_attributes: hSupp.value.split(',').map(s => s.trim()).filter(Boolean),
          refuting_attributes: hRef.value.split(',').map(s => s.trim()).filter(Boolean),
        }),
      });
      if (snapshot) snapshot.operations = res.operations;
      renderView();
    } catch (err) {
      message(err.message, true);
    }
  };
  achForm.append(hTitle, hSupp, hRef, addHypBtn);
  achPanel.body.append(achForm);

  const achWrap = text('div', null, 'panel table-wrap');
  const achTable = document.createElement('table');
  achTable.className = 'ach-matrix-table';
  const thead = document.createElement('thead');
  const htr = document.createElement('tr');
  ['HYPOTHESIS', 'ASSESSMENT', 'CONFIDENCE', ' WEIGHTED SUPPORT', 'WEIGHTED REFUTE', 'CITED FACTS'].forEach(col => htr.append(text('th', col)));
  thead.append(htr);
  achTable.append(thead);
  const tbody = document.createElement('tbody');
  (ops.ach_ranked || ops.hypotheses || []).forEach(h => {
    const tr = document.createElement('tr');
    const titleTd = text('td');
    titleTd.append(text('strong', h.title), text('div', h.description || '', 'muted'));
    const statusTd = text('td');
    statusTd.append(text('span', h.assessment || 'UNDECIDED', 'tag'));
    tr.append(
      titleTd,
      statusTd,
      text('td', `${h.confidence_pct ?? 50}%`, 'mono'),
      text('td', `+${h.support_score ?? 0} (${h.supporting_count ?? 0})`, 'mono'),
      text('td', `-${h.refute_score ?? 0} (${h.refuting_count ?? 0})`, 'mono'),
      text('td', (h.supporting_fact_ids || []).slice(0, 4).join(', ') || '—', 'mono muted')
    );
    tbody.append(tr);
  });
  achTable.append(tbody);
  achWrap.append(achTable);
  achPanel.body.append(achWrap);
  view.append(achPanel.root);

  // 5. Team Webhook & Continuous Delta Alerting (Slack / Discord / Generic HTTPS)
  const wh = ops.webhook || {url: '', provider: 'slack', enabled: false};
  const whPanel = panel('Team Webhook & Continuous Delta Alerting · Slack / Discord / HTTPS');
  whPanel.body.append(
    text('p', 'Push real-time operational notifications to a shared Slack channel, Discord channel, or SIEM/SOAR webhook whenever attack surface deltas or high-severity exposures are detected.', 'notice')
  );
  const whBar = text('div', null, 'ops-diff-bar');
  const whProv = document.createElement('select');
  whProv.setAttribute('aria-label', 'Webhook provider');
  [['slack', 'Slack Incoming Webhook'], ['discord', 'Discord Webhook'], ['generic', 'Generic HTTPS JSON Webhook']].forEach(([v, l]) => {
    const o = text('option', l);
    o.value = v;
    whProv.append(o);
  });
  whProv.value = wh.provider || 'slack';
  const whUrl = document.createElement('input');
  whUrl.type = 'text';
  whUrl.placeholder = 'https://hooks.slack.com/services/… or Discord webhook URL';
  whUrl.value = wh.url || '';
  const saveWhBtn = text('button', 'Save Webhook', 'primary');
  saveWhBtn.type = 'button';
  saveWhBtn.onclick = async () => {
    try {
      const res = await api('/api/operations/webhook', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-Workspace-Token': session},
        body: JSON.stringify({
          url: whUrl.value.trim(),
          provider: whProv.value,
          enabled: Boolean(whUrl.value.trim()),
        }),
      });
      if (snapshot) snapshot.operations = res.operations;
      message(`Saved ${whProv.value.toUpperCase()} team webhook configuration.`);
      renderView();
    } catch (err) {
      message(err.message, true);
    }
  };
  const testWhBtn = text('button', 'Send Test Alert', 'secondary');
  testWhBtn.type = 'button';
  testWhBtn.onclick = async () => {
    testWhBtn.disabled = true;
    testWhBtn.textContent = 'Sending…';
    try {
      const res = await api('/api/operations/webhook/test', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-Workspace-Token': session},
        body: JSON.stringify({
          title: `Find3r Partner Alert · ${subjectLabel()}`,
          summary: `Operator ${operatorCallsign} triggered a live dossier alert for ${subjectLabel()} (Grade ${brief?.posture?.overall?.letter || 'N/A'}).`,
        }),
      });
      message(res.sent ? `Delivered live alert to ${res.provider || 'webhook'} (HTTP ${res.http_status}).` : (res.error || 'Webhook test failed.'), !res.sent);
    } catch (err) {
      message(err.message, true);
    } finally {
      testWhBtn.disabled = false;
      testWhBtn.textContent = 'Send Test Alert';
    }
  };
  whBar.append(whProv, whUrl, saveWhBtn, testWhBtn);
  whPanel.body.append(whBar);
  view.append(whPanel.root);
}

// =========================================================================
// GLOBAL CMD+K / CTRL+K COMMAND & PIVOT PALETTE
// =========================================================================
let cmdkActiveIdx = 0, cmdkCurrentItems = [];

function buildCmdKItems(query) {
  const q = (query || '').trim().toLowerCase();
  const items = [];

  // Quick Workspace & Tab Actions
  const actions = [
    {label: 'Workspace: Command & Launch Omnibar', meta: 'ACTION · WORKSPACE', run: () => setWorkspaceView('command')},
    {label: 'Workspace: Ephemeral Cloud Nodes (Vultr VPS)', meta: 'ACTION · CLOUD', run: () => setWorkspaceView('cloud')},
    {label: 'Workspace: Agent Harness & Local Ollama AI', meta: 'ACTION · AI HARNESS', run: () => setWorkspaceView('harness')},
    {label: 'Workspace: OSINT Sensors & Tool Installer', meta: 'ACTION · SENSORS', run: () => setWorkspaceView('tools')},
    {label: 'Configure API Keys & Monthly Budget', meta: 'ACTION · SETTINGS', run: () => openSettings()},
  ];
  if (brief) {
    actions.unshift(
      {label: `Open Operations, Run Diff & ACH Matrix (${subjectLabel()})`, meta: 'TAB · OPERATIONS', run: () => setTab('operations')},
      {label: `Open Geo-IP & ASN Infrastructure Map (${subjectLabel()})`, meta: 'TAB · GEO MAP', run: () => setTab('map')},
      {label: `Open Entity Graph & Shortest-Path Finder (${subjectLabel()})`, meta: 'TAB · ENTITY GRAPH', run: () => setTab('graph')},
      {label: `Open Overview & A–F Security Posture (${subjectLabel()})`, meta: 'TAB · OVERVIEW', run: () => setTab('overview')},
      {label: `Open All Guarded Evidence (${brief.facts?.length || 0} facts)`, meta: 'TAB · EVIDENCE', run: () => setTab('evidence')},
      {label: `Export OASIS STIX 2.1 Threat Intel Bundle (.json)`, meta: 'EXPORT · STIX 2.1', run: () => downloadMaltego('stix.json')},
      {label: `Export Print-Ready Executive HTML Dossier (.html)`, meta: 'EXPORT · HTML DOSSIER', run: () => downloadMaltego('dossier.html')},
      {label: `Export Maltego GraphML (.graphml)`, meta: 'EXPORT · MALTEGO', run: () => downloadMaltego('maltego.graphml')}
    );
  }
  actions.forEach(a => {
    if (!q || a.label.toLowerCase().includes(q) || a.meta.toLowerCase().includes(q)) {
      items.push(a);
    }
  });

  // Stored Runs
  (snapshot?.runs || []).forEach(r => {
    const lbl = subjectLabel(r);
    if (!q || lbl.toLowerCase().includes(q) || (r.subject_kind || '').toLowerCase().includes(q)) {
      items.push({
        label: `Open Run: ${lbl}`,
        meta: `RUN · ${(r.subject_kind || 'domain').toUpperCase()} · ${r.id.slice(0, 8)}`,
        run: () => openRun(r.id),
      });
    }
  });

  // Current Brief Entities & Facts
  if (brief && q.length >= 2) {
    (brief.graph?.nodes || []).slice(0, 40).forEach(n => {
      if ((n.label || '').toLowerCase().includes(q) || (n.kind || '').toLowerCase().includes(q)) {
        items.push({
          label: `Inspect Entity: ${n.label}`,
          meta: `ENTITY · ${(n.kind || '').toUpperCase()}`,
          run: () => {
            setTab('graph');
            showEntityTransformInspector(n);
          },
        });
      }
    });
    (brief.facts || []).slice(0, 80).forEach(f => {
      if ((f.attribute || '').toLowerCase().includes(q) || String(f.value || '').toLowerCase().includes(q) || (f.subject || '').toLowerCase().includes(q)) {
        items.push({
          label: `${f.attribute}: ${String(f.value).slice(0, 48)}`,
          meta: `FACT · ${f.admiralty || 'C3'} · ${f.source}`,
          run: () => showSource(f),
        });
      }
    });
  }

  if (q && isPivotableValue(q, 'auto')) {
    items.unshift({
      label: `Launch Live Investigation on "${query.trim()}"`,
      meta: 'PIVOT · NEW INVESTIGATION',
      run: () => {
        setWorkspaceView('command');
        if ($('#seed-kind')) $('#seed-kind').value = 'auto';
        $('#domain').value = query.trim();
        updateSeedInputNotice();
        $('#investigate').requestSubmit?.();
      },
    });
  }

  return items.slice(0, 18);
}

function renderCmdKResults() {
  const list = $('#cmdk-results');
  if (!list) return;
  const query = $('#cmdk-input')?.value || '';
  cmdkCurrentItems = buildCmdKItems(query);
  if (cmdkActiveIdx >= cmdkCurrentItems.length) cmdkActiveIdx = 0;
  list.replaceChildren();
  cmdkCurrentItems.forEach((item, idx) => {
    const btn = text('button', null, 'cmdk-item' + (idx === cmdkActiveIdx ? ' active' : ''));
    btn.type = 'button';
    btn.append(text('span', item.label, 'cmdk-item-label'), text('span', item.meta, 'cmdk-item-meta'));
    btn.onclick = () => {
      $('#cmdk-dialog')?.close();
      item.run();
    };
    list.append(btn);
  });
}

function openCmdK() {
  const dlg = $('#cmdk-dialog');
  if (!dlg) return;
  cmdkActiveIdx = 0;
  if ($('#cmdk-input')) $('#cmdk-input').value = '';
  renderCmdKResults();
  dlg.showModal();
  $('#cmdk-input')?.focus?.();
}

if ($('#open-cmdk')) $('#open-cmdk').onclick = openCmdK;
if ($('#close-cmdk')) $('#close-cmdk').onclick = () => $('#cmdk-dialog')?.close();
if ($('#cmdk-input')) {
  $('#cmdk-input').addEventListener('input', () => {
    cmdkActiveIdx = 0;
    renderCmdKResults();
  });
  $('#cmdk-input').addEventListener('keydown', e => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      cmdkActiveIdx = (cmdkActiveIdx + 1) % Math.max(1, cmdkCurrentItems.length);
      renderCmdKResults();
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      cmdkActiveIdx = (cmdkActiveIdx - 1 + Math.max(1, cmdkCurrentItems.length)) % Math.max(1, cmdkCurrentItems.length);
      renderCmdKResults();
    } else if (e.key === 'Enter' && cmdkCurrentItems[cmdkActiveIdx]) {
      e.preventDefault();
      const chosen = cmdkCurrentItems[cmdkActiveIdx];
      $('#cmdk-dialog')?.close();
      chosen.run();
    }
  });
}
if (typeof window !== 'undefined' && window.addEventListener) {
  window.addEventListener('keydown', e => {
    if ((e.metaKey || e.ctrlKey) && e.key?.toLowerCase() === 'k') {
      e.preventDefault();
      openCmdK();
    }
  });
}

function renderAnalysis(view) {
  const box = panel('Agent Harness');
  box.body.append(text('p', 'Source adapters collect the evidence. Deterministic rules organize it; selected cloud or local Ollama models can add cited inferences. Models receive eligible facts, including public email/profile evidence when applicable. They cannot browse, use tools, or edit observations.', 'notice'));
  const cloudAvailable = (snapshot?.runtime_providers || []).filter(p => p.ready).map(p => ({
    provider: p.provider,
    label: `${p.provider} · ${p.model}`,
  }));
  const ollamaAvailable = (snapshot?.ollama?.catalog || []).map(m => ({
    provider: `ollama:${m.id}`,
    label: `ollama (local $0) · ${m.id} (${m.label})`,
  }));
  const available = [...ollamaAvailable, ...cloudAvailable];
  const form = document.createElement('form');
  const mode = document.createElement('select');
  mode.setAttribute('aria-label', 'Agent harness analysis mode');
  for (const [value, label] of [['deterministic', 'Deterministic · no model calls'], ['single', 'Single model · one cited synthesis'], ['multi', 'Multi-model · specialists + reviewer']]) {
    const option = text('option', label);
    option.value = value;
    option.disabled = value === 'single' ? !available.length : value === 'multi' && available.length < 2;
    mode.append(option);
  }
  mode.value = harnessMode;
  const choices = text('div', null, 'model-choices');
  available.forEach(p => {
    const label = text('label', null, 'contact-option');
    const input = document.createElement('input');
    input.type = 'checkbox';
    input.name = 'provider';
    input.value = p.provider;
    input.checked = harnessProviders.includes(p.provider);
    input.disabled = mode.value === 'deterministic';
    label.append(input, text('span', p.label));
    input.onchange = () => {
      if (mode.value === 'single' && input.checked) {
        choices.querySelectorAll('input').forEach(other => { if (other !== input) other.checked = false; });
      }
    };
    choices.append(label);
  });
  mode.onchange = () => {
    choices.querySelectorAll('input').forEach(i => i.disabled = mode.value === 'deterministic');
  };
  const run = text('button', 'Run selected analysis', 'primary');
  run.type = 'submit';
  const status = text('p', available.length ? 'Every output remains tentative and requires human review.' : 'No runtime providers are ready. Click "API KEYS & SETTINGS" in the top bar to configure OpenAI, Anthropic, Gemini, or DeepSeek.', 'notice');
  form.append(mode, choices, run, status);
  form.onsubmit = async e => {
    e.preventDefault();
    const providers = [...choices.querySelectorAll('input:checked')].map(i => i.value);
    run.disabled = true;
    try {
      validateHarness(mode.value, providers);
      harnessMode = mode.value;
      harnessProviders = providers;
      renderHarness();
      if (mode.value === 'deterministic') {
        status.textContent = 'Deterministic evidence views are ready. No model request was made.';
        return;
      }
      status.textContent = 'Running bounded analysis. Selected providers receive the eligible cited facts…';
      const runId = brief.run_id;
      const result = await api(`/api/runs/${runId}/analysis`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-Workspace-Token': session},
        body: JSON.stringify({mode: mode.value, providers}),
      });
      if (brief?.run_id !== runId) return;
      brief.model_analysis = result;
      status.textContent = result.status === 'complete' ? 'Analysis complete. Review the cited inferences.' : result.reason || 'Analysis finished with gaps. Review each worker outcome.';
      renderModelResult(box.body, result);
    } catch (err) {
      status.textContent = err.message;
    } finally {
      run.disabled = false;
    }
  };
  box.body.append(form);
  view.append(box.root);
  if (brief.model_analysis) renderModelResult(box.body, brief.model_analysis);
}

function renderModelResult(root, result) {
  root.querySelector('.model-result')?.remove();
  const container = text('div', null, 'model-result analysis-results');
  const summary = text('div', null, 'analysis-summary');
  summary.append(text('span', `${result.mode?.toUpperCase() || 'ANALYSIS'} · ${result.status?.toUpperCase() || 'UNKNOWN'}`, 'mono'), text('span', `Conservative charge: $${Number(result.spend_usd || 0).toFixed(4)}`, 'mono muted'));
  container.append(summary);
  const reports = text('div', null, 'rollout');
  (result.reports || []).forEach(report => {
    const item = text('div', null, 'rollout-step');
    item.append(text('strong', report.role.replaceAll('_', ' ')), text('p', `${report.provider} · ${report.model}`), text('p', `${report.status} · $${Number(report.cost_usd || 0).toFixed(4)}`));
    if (report.reason) item.append(text('p', report.reason));
    reports.append(item);
  });
  container.append(reports);
  const box = panel('Cited model conclusions · inference, human review required');
  if (!(result.claims || []).length) box.body.append(text('p', result.reason || 'No validated conclusions were produced. This is not evidence that the subject has no relevant public information.', 'notice'));
  (result.claims || []).forEach(claim => {
    const item = text('div', null, 'requirement');
    item.append(text('span', 'INFERENCE · HUMAN REVIEW REQUIRED', 'status warning'), text('h3', claim.text));
    (claim.evidence_ids || []).forEach(id => {
      const fact = brief.facts.find(f => f.fact_id === id);
      if (fact) item.append(sourceButton(fact));
    });
    box.body.append(item);
  });
  container.append(box.root);
  root.append(container);
}

$('#export-report').onclick = () => {
  if (!brief) return;
  const safe = v => String(v ?? '').replace(/[\r\n]/g, ' ').replace(/[<>]/g, c => c === '<' ? '&lt;' : '&gt;').replace(/`/g, "'");
  const posture = brief.posture || {};
  const overall = posture.overall || {letter: 'N/A', score: null, rationale: ''};
  const exposures = brief.exposures || [];

  const lines = [
    `# Find3r Executive Intelligence Dossier · ${safe(subjectLabel())}`,
    '',
    `Run ID: \`${brief.run_id}\` | Subject Kind: \`${safe(subjectKind())}\` | Status: **${safe(brief.status)}** (${safe(brief.stop_reason)})`,
    `Exported Facts: **${brief.facts.length}** | Prioritized Exposures: **${exposures.length}** | Overall Posture Grade: **${overall.letter}** (${overall.score ?? 'N/A'})`,
    '',
    '## Security Posture Assessment (A–F)',
    '',
    `**Overall Grade: ${overall.letter}** (${overall.score !== null ? overall.score + '/100' : 'unscored'}) — ${safe(overall.rationale)}`,
    '',
    '| Security Domain | Grade | Score | Rationale |',
    '| :--- | :---: | :---: | :--- |',
  ];
  for (const cat of Object.values(posture.categories || {})) {
    lines.push(`| ${safe(cat.label)} | **${cat.letter}** | ${cat.score !== null ? cat.score + '/100' : 'N/A'} | ${safe(cat.rationale)} |`);
  }
  lines.push('', '## Prioritized Exposures & Remediation Roadmap', '');
  if (!exposures.length) {
    lines.push('No actionable security exposures triggered from observed facts in this run.', '');
  } else {
    exposures.forEach(exp => {
      lines.push(
        `### [${exp.severity.toUpperCase()}] ${safe(exp.title)} (${safe(exp.category)})`,
        `- **Observed:** \`${safe(exp.observed)}\``,
        `- **Business Impact:** ${safe(exp.consequence)}`,
        `- **Recommended Remediation:** ${safe(exp.remediation)}`,
        `- **Owner / Stakeholder:** ${safe(exp.stakeholder_function)}`,
        `- **Evidence IDs:** ${(exp.evidence_ids || []).join(', ') || 'none'}`,
        ''
      );
    });
  }
  lines.push('## Explained scores', '');
  for (const [key, label] of [['commercial_fit', 'Commercial fit'], ['security_needs', 'Evidence of potential security needs']]) {
    const s = isNonCompanyBrief() ? null : brief.scores?.[key];
    if (!s) continue;
    lines.push(`${label}: ${s.score === null ? 'unassessed' : s.score + '/100'}; coverage ${s.coverage}%.`, s.explanation, '');
    s.criteria.forEach(c => lines.push(`- ${safe(c.label)}: ${c.status}; weight ${c.weight}; contribution ${c.contribution ?? 'unknown'}; evidence ${c.evidence_ids.join(', ') || 'none'}. ${safe(c.explanation)}`));
  }
  lines.push('', '## Observations and source records', '');
  brief.facts.forEach(f => lines.push(
    `- [${f.fact_id}] ${safe(f.subject)}: ${safe(f.attribute)} = ${safe(f.value)}`,
    `  Source: ${safe(f.source_url)}; collected ${safe(f.collected_at)}; retrieved by ${safe(f.retrieved_by || f.source)}; grade ${f.admiralty}; confidence ${f.confidence}; source record ${f.source_record_id}.`,
    ''
  ));
  lines.push('## Requirements and gaps', '');
  brief.requirements.forEach(r => lines.push(`- ${safe(r.question)}: ${r.status}. ${safe(r.gap_reason || '')}`));
  brief.skipped.forEach(s => lines.push(`- ${safe(s.adapter)}: ${safe(s.reason)}`));
  if (brief.model_analysis) {
    lines.push('', '## Model analysis · tentative inferences for human review', '');
    (brief.model_analysis.claims || []).forEach(c => lines.push(`- ${safe(c.text)} [${c.evidence_ids.join(', ')}]`));
  }
  const url = URL.createObjectURL(new Blob([lines.join('\n')], {type: 'text/markdown;charset=utf-8'}));
  const a = document.createElement('a');
  a.href = url;
  a.download = `find3r-${brief.run_id}.md`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
};
