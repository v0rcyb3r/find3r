'use strict';
const $ = (s) => document.querySelector(s);
const text = (tag, value, cls) => { const el = document.createElement(tag); el.textContent = value ?? ''; if (cls) el.className = cls; return el; };
let session = '', snapshot = null, brief = null, tab = 'overview', selectedRun = null, polling = false;
let harnessMode = 'deterministic', harnessProviders = [], deleteTarget = null;
let graphZoom = 1, graphKindFilter = 'all', workspaceView = 'command';
let runSearchQuery = '', runKindFilter = 'all', operatorCallsign = 'local-analyst';

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
  const response = await fetch(path, {cache:'no-store', ...options});
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

  if (isPivotableValue(fact.value, fact.attribute)) {
    const pivotVal = fact.value.trim();
    const actions = text('div', null, 'export-actions source-pivot-bar');
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
    actions.append(pivotBtn);
    root.append(actions);
  }

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

  if (tab === 'graph') { renderGraph(view); return; }
  if (tab === 'analysis') { renderAnalysis(view); return; }

  if (tab === 'infrastructure' && isEmailBrief()) {
    view.append(
      text('p', 'Domain and network context describes the provider or public mentions, not verified personal infrastructure.', 'notice email-context'),
      table(brief.facts.filter(f => /^(email\.domain|email\.syntax|public\.email\.(syntax|local_part|mailbox_type|provider|deliverable_mx|mx_host|domain_spf|domain_dmarc|checked_services)|dns|host|whois|intelx)\./.test(f.attribute + '.')), true)
    );
    return;
  }
  if (tab === 'infrastructure') {
    view.append(
      text('p', 'DNS, TLS certificates, HTTP headers, Shodan InternetDB ports/CVEs, RDAP registration, passive subdomains, and web technology fingerprints.', 'notice'),
      table(brief.facts.filter(f => /^(dns|dnssec|tls|http|ip|host|whois|tech|web|discovery|intelx|email\.(dmarc|spf|dkim|mtasts|tlsrpt))\./.test(f.attribute)), true)
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
    const publicFacts = brief.facts.filter(f => !isRegistration(f) && /^(public|email\.public|person|intelx)\./.test(f.attribute));
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
    catalog.slice(0, 8).forEach(m => {
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
  if ($('#operator-session-state')) {
    $('#operator-session-state').textContent = session ? `ACTIVE · TOKEN ${session.slice(0, 8)}…` : 'LOCAL SESSION';
  }
  if ($('#operator-node-state')) {
    $('#operator-node-state').textContent = $('#header-node-status') ? $('#header-node-status').textContent : 'LOCAL WORKSPACE';
  }
  if ($('#operator-callsign')) {
    $('#operator-callsign').value = operatorCallsign;
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
  $('#operator-form').addEventListener('submit', e => {
    e.preventDefault();
    const val = ($('#operator-callsign')?.value || '').trim() || 'local-analyst';
    operatorCallsign = val;
    if ($('#operator-login-btn')) {
      $('#operator-login-btn').textContent = `OPERATOR: ${val.toUpperCase()} · STAGED`;
    }
    $('#operator-dialog').close();
    message(`Active operator callsign set to "${val}".`);
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

  (graph.edges || []).forEach(edge => {
    const a = positions.get(edge.source), b = positions.get(edge.target);
    if (!a || !b) return;
    const path = document.createElementNS(ns, 'path');
    const x1 = a.x + NODE_W, y1 = a.y + 18, x2 = b.x, y2 = b.y + 18;
    path.setAttribute('d', `M${x1},${y1} C${x1 + 45},${y1} ${x2 - 45},${y2} ${x2},${y2}`);
    path.setAttribute('class', 'graph-edge');
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
    const rect = document.createElementNS(ns, 'rect');
    rect.setAttribute('width', NODE_W);
    rect.setAttribute('height', 38);
    rect.setAttribute('rx', 10);
    rect.setAttribute('ry', 10);
    rect.setAttribute('class', 'graph-node');
    const label = document.createElementNS(ns, 'text');
    label.setAttribute('x', 12);
    label.setAttribute('y', 24);
    label.setAttribute('class', 'graph-node-label');
    label.textContent = node.label.length > MAXLEN ? node.label.slice(0, MAXLEN - 1) + '…' : node.label;
    const title = document.createElementNS(ns, 'title');
    title.textContent = node.label;
    g.append(rect, label, title);
    svg.append(g);
  });
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
}

function renderAnalysis(view) {
  const box = panel('Agent Harness');
  box.body.append(text('p', 'Source adapters collect the evidence. Deterministic rules organize it; selected cloud or local Ollama models can add cited inferences. Models receive eligible facts, including public email/profile evidence when applicable. They cannot browse, use tools, or edit observations.', 'notice'));
  const cloudAvailable = (snapshot?.runtime_providers || []).filter(p => p.ready).map(p => ({
    provider: p.provider,
    label: `${p.provider} · ${p.model}`,
  }));
  const ollamaAvailable = (snapshot?.ollama?.catalog || []).slice(0, 8).map(m => ({
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
  const run = text('button', 'Run selected analysis · $1 cap', 'primary');
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
