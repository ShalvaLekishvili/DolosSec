const $ = (id) => document.getElementById(id);
const state = { runId: null, eventSource: null, browserPath: null, browserParent: null };

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>'"]/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[ch]));
}
function show(el, yes=true) { el.classList.toggle('hidden', !yes); }
function setError(message='') { $('form-error').textContent = message; show($('form-error'), Boolean(message)); }
function timeOnly(ts) { try { return new Date(ts).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit'}); } catch { return ''; } }

async function api(url, options={}) {
  const res = await fetch(url, { headers: {'Content-Type':'application/json', ...(options.headers||{})}, ...options });
  if (!res.ok) {
    let detail = `Request failed (${res.status})`;
    try {
      const body = await res.json();
      if (Array.isArray(body.detail)) detail = body.detail.map(x => x.msg || String(x)).join('; ');
      else detail = body.detail || detail;
    } catch {}
    throw new Error(String(detail));
  }
  return res.json();
}

async function health() {
  try {
    const h = await api('/api/health');
    $('planner-pill').textContent = `Planner: ${h.planner}${h.model ? ` / ${h.model}` : ''}`;
    $('engine-detail').textContent = `Browse root: ${h.browse_root}`;
  } catch {
    $('engine-status').textContent = 'Engine unavailable';
  }
}

function selectTargetType(type) {
  $('target-type').value = type;
  document.querySelectorAll('.target-tab').forEach(btn => btn.classList.toggle('active', btn.dataset.targetType === type));
  show($('local-target-field'), type === 'local_path');
  show($('url-target-field'), type === 'url');
  show($('authorization-fields'), type === 'url');
  setError();
}

document.querySelectorAll('.target-tab').forEach(btn => btn.addEventListener('click', () => selectTargetType(btn.dataset.targetType)));
document.querySelectorAll('.mode-option').forEach(label => label.addEventListener('click', () => {
  document.querySelectorAll('.mode-option').forEach(x => x.classList.remove('selected'));
  label.classList.add('selected');
}));
document.querySelectorAll('[data-scroll]').forEach(btn => btn.addEventListener('click', () => $(btn.dataset.scroll)?.scrollIntoView({behavior:'smooth'})));

async function loadDirectory(path=null) {
  const data = await api(`/api/fs${path ? `?path=${encodeURIComponent(path)}` : ''}`);
  state.browserPath = data.path; state.browserParent = data.parent;
  $('browser-path').textContent = data.path;
  $('browser-parent').disabled = !data.parent;
  $('browser-list').innerHTML = data.directories.length ? data.directories.map(d => `
    <button type="button" class="browser-entry" data-path="${escapeHtml(d.path)}"><span class="folder-icon">▰</span><span>${escapeHtml(d.name)}</span></button>
  `).join('') : '<div class="empty-state">No subdirectories visible here.</div>';
  $('browser-list').querySelectorAll('[data-path]').forEach(btn => btn.addEventListener('click', () => loadDirectory(btn.dataset.path).catch(e => setError(e.message))));
}

$('browse-button').addEventListener('click', async () => {
  try { await loadDirectory($('local-path').value || null); } catch { await loadDirectory(null); }
  show($('browser-modal'), true);
});
$('close-browser').addEventListener('click', () => show($('browser-modal'), false));
$('browser-parent').addEventListener('click', () => state.browserParent && loadDirectory(state.browserParent));
$('select-folder').addEventListener('click', () => { if (state.browserPath) $('local-path').value = state.browserPath; show($('browser-modal'), false); });
$('browser-modal').addEventListener('click', (e) => { if (e.target === $('browser-modal')) show($('browser-modal'), false); });

function resetRunUi(run) {
  $('run-status').textContent = 'Starting assessment…';
  $('run-pulse').className = 'pulse running';
  $('metric-run-id').textContent = run.run_id;
  $('metric-target').textContent = run.target;
  $('metric-mode').textContent = run.mode;
  $('metric-findings').textContent = '0';
  $('timeline').innerHTML = '';
  $('findings').innerHTML = '<div class="empty-state">Waiting for evidence…</div>';
  $('finding-summary').textContent = '0 findings';
  $('report-view').textContent = 'Assessment in progress. The final report will appear here automatically.';
  show($('artifact-actions'), false);
}

function renderEvent(evt) {
  const type = evt.type || 'progress';
  const detail = evt.data?.reason || evt.data?.summary || (evt.data?.error ? `Error: ${evt.data.error}` : '');
  const item = document.createElement('div');
  item.className = `timeline-item ${type}`;
  item.innerHTML = `<span class="timeline-icon"></span><div class="timeline-message"><strong>${escapeHtml(evt.message || type)}</strong>${detail ? `<small>${escapeHtml(detail)}</small>` : ''}</div><span class="timeline-time">${escapeHtml(timeOnly(evt.timestamp))}</span>`;
  $('timeline').appendChild(item);
  if ($('timeline').children.length > 60) $('timeline').firstElementChild.remove();

  if (type === 'findings_updated') renderFindings(evt.data?.findings || []);
  if (type === 'run_finished') { $('run-status').textContent = 'Completed'; $('run-pulse').className = 'pulse complete'; }
  else if (type === 'run_failed') { $('run-status').textContent = 'Failed'; $('run-pulse').className = 'pulse failed'; }
  else if (!['findings_updated'].includes(type)) $('run-status').textContent = evt.message || 'Running';
}

function renderFindings(findings) {
  $('metric-findings').textContent = findings.length;
  $('finding-summary').textContent = `${findings.length} finding${findings.length === 1 ? '' : 's'}`;
  if (!findings.length) { $('findings').innerHTML = '<div class="empty-state">No findings produced by the enabled checks so far.</div>'; return; }
  $('findings').innerHTML = findings.map(f => `
    <article class="finding">
      <div class="finding-top"><div><h3>${escapeHtml(f.title)}</h3><div class="finding-meta"><span class="severity ${escapeHtml(f.severity)}">${escapeHtml(f.severity)}</span><span>${escapeHtml(f.id)}</span><span>${Math.round((f.confidence || 0) * 100)}% confidence</span></div></div></div>
      <p>${escapeHtml(f.description)}</p>
      ${(f.evidence || []).map(e => `<div class="evidence">${escapeHtml(e)}</div>`).join('')}
    </article>
  `).join('');
}

async function finalizeRun(runId) {
  try {
    const run = await api(`/api/runs/${encodeURIComponent(runId)}`);
    renderFindings(run.findings || []);
    if (run.report) $('report-view').textContent = run.report;
    if (run.error) $('report-view').textContent = `Assessment failed:\n${run.error}`;
    $('run-status').textContent = run.status === 'completed' ? 'Completed' : run.status;
    $('run-pulse').className = `pulse ${run.status === 'completed' ? 'complete' : run.status === 'failed' ? 'failed' : 'running'}`;
    if (run.status === 'completed') {
      $('download-report').href = `/api/runs/${runId}/download/report`;
      $('download-findings').href = `/api/runs/${runId}/download/findings`;
      $('download-audit').href = `/api/runs/${runId}/download/audit`;
      show($('artifact-actions'), true);
    }
  } catch (e) { console.error(e); }
}

function streamRun(runId) {
  if (state.eventSource) state.eventSource.close();
  const es = new EventSource(`/api/runs/${encodeURIComponent(runId)}/events`);
  state.eventSource = es;
  es.addEventListener('progress', e => { try { renderEvent(JSON.parse(e.data)); } catch (err) { console.error(err); } });
  es.addEventListener('done', () => { es.close(); finalizeRun(runId); });
  es.onerror = () => { if (es.readyState === EventSource.CLOSED) finalizeRun(runId); };
}

$('scan-form').addEventListener('submit', async (e) => {
  e.preventDefault(); setError();
  const type = $('target-type').value;
  const mode = document.querySelector('input[name="mode"]:checked').value;
  const target = type === 'local_path' ? $('local-path').value.trim() : $('target-url').value.trim();
  if (!target) return setError(type === 'local_path' ? 'Choose or enter a local directory.' : 'Enter a target URL.');

  const body = { target_type: type, target, mode, allow_private_networks: $('allow-private').checked };
  if (type === 'url') {
    body.authorization = {
      owner: $('auth-owner').value.trim(), ticket: $('auth-ticket').value.trim(), purpose: $('auth-purpose').value.trim(), expires_hours: Number($('auth-expiry').value)
    };
  }
  try {
    const run = await api('/api/runs', { method:'POST', body:JSON.stringify(body) });
    state.runId = run.run_id;
    resetRunUi(run);
    streamRun(run.run_id);
    $('live-panel').scrollIntoView({behavior:'smooth', block:'start'});
  } catch (err) { setError(err.message); }
});

health();
